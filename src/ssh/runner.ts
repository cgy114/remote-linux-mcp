import { spawn, type ChildProcess } from 'node:child_process';
import { shSingleQuote } from '../policy/shell.js';
import type { RunResult } from '../types.js';
import { resolveSshBinary, resolveToolBinary } from './binary.js';

const IS_WIN = process.platform === 'win32';
const EXIT_GRACE_MS = 2000;
const KILL_WAIT_MS = 5000;

// ---------- 进程登记 ----------

const tracked = new Set<ChildProcess>();

/** 登记子进程；返回注销函数。 */
export function trackChild(child: ChildProcess): () => void {
  tracked.add(child);
  return () => {
    tracked.delete(child);
  };
}

/** 杀掉所有仍登记的子进程树（尽力而为，不抛）。 */
export async function killAllTrackedChildren(): Promise<void> {
  const children = [...tracked];
  let taskkill = 'taskkill';
  if (IS_WIN) {
    try {
      taskkill = await resolveToolBinary('taskkill');
    } catch {
      taskkill = 'taskkill';
    }
  }
  await Promise.all(
    children.map(async (child) => {
      if (child.pid !== undefined) await killTree(child.pid, taskkill);
      tracked.delete(child);
    }),
  );
}

// ---------- UTF-8 边界安全的截断 ----------

/** 去掉末尾不完整的 UTF-8 字符（只看 buffer 自身）。 */
function trimIncompleteTail(b: Buffer): Buffer {
  const len = b.length;
  for (let i = len - 1; i >= Math.max(0, len - 4); i--) {
    const c = b[i]!;
    if ((c & 0xc0) === 0x80) continue;
    const needed = c >= 0xf0 ? 4 : c >= 0xe0 ? 3 : c >= 0xc0 ? 2 : 1;
    return len - i < needed ? b.subarray(0, i) : b;
  }
  return b;
}

/** 去掉开头不属于完整字符的续字节。 */
function trimLeadingPartial(b: Buffer): Buffer {
  const limit = Math.min(4, b.length);
  for (let i = 0; i < limit; i++) {
    if ((b[i]! & 0xc0) !== 0x80) return b.subarray(i);
  }
  return limit >= b.length ? b.subarray(b.length) : b;
}

/** 由头部、尾部字节与原始总长生成截断后的文本。 */
function assembleTruncated(
  head: Buffer,
  tail: Buffer,
  total: number,
): { text: string; truncated: boolean } {
  const h = trimIncompleteTail(head);
  const t = trimLeadingPartial(tail);
  const dropped = total - h.length - t.length;
  return {
    text: `${h.toString('utf8')}\n...[truncated ${dropped} bytes]...\n${t.toString('utf8')}`,
    truncated: true,
  };
}

/** 按 UTF-8 字节数截断文本：保留头约 50%、尾约 50%，不切断多字节字符。 */
export function truncateOutput(
  text: string,
  maxBytes: number,
): { text: string; truncated: boolean } {
  const buf = Buffer.from(text, 'utf8');
  if (buf.length <= maxBytes) return { text, truncated: false };
  const headCap = Math.floor(maxBytes / 2);
  const tailCap = maxBytes - headCap;
  return assembleTruncated(
    buf.subarray(0, headCap),
    buf.subarray(buf.length - tailCap),
    buf.length,
  );
}

/**
 * 收集流输出。超过 maxBytes 时只保留头部与尾部（内存有界），中间用标记替代。
 */
export function captureStream(
  stream: NodeJS.ReadableStream,
  maxBytes: number,
  opts?: { onBytes?: (total: number) => void },
): Promise<{ text: string; truncated: boolean }> {
  return new Promise((resolve) => {
    const headCap = Math.floor(maxBytes / 2);
    const tailCap = maxBytes - headCap;
    const headChunks: Buffer[] = [];
    let headLen = 0;
    let tailChunks: Buffer[] = [];
    let tailLen = 0;
    let total = 0;
    let settled = false;

    const finish = (): void => {
      if (settled) return;
      settled = true;
      try {
        opts?.onBytes?.(total);
      } catch {
        // 回调失败不影响捕获结果
      }
      const head = Buffer.concat(headChunks, headLen);
      const tailAll = Buffer.concat(tailChunks, tailLen);
      if (total <= maxBytes) {
        // 未超限：头部 + 尾部拼接即全部内容
        resolve({ text: Buffer.concat([head, tailAll]).toString('utf8'), truncated: false });
        return;
      }
      resolve(assembleTruncated(head, tailAll.subarray(tailAll.length - tailCap), total));
    };

    stream.on('data', (chunk: Buffer | string) => {
      const buf = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
      total += buf.length;
      let rest = buf;
      if (headLen < headCap) {
        const take = Math.min(headCap - headLen, rest.length);
        headChunks.push(rest.subarray(0, take));
        headLen += take;
        rest = rest.subarray(take);
      }
      if (rest.length > 0) {
        tailChunks.push(rest);
        tailLen += rest.length;
        if (tailLen > tailCap * 2) {
          const merged = Buffer.concat(tailChunks, tailLen);
          tailChunks = [merged.subarray(merged.length - tailCap)];
          tailLen = tailCap;
        }
      }
    });
    stream.on('end', finish);
    stream.on('close', finish);
    stream.on('error', finish);
  });
}

// ---------- 超时与退出 ----------

export interface ExitInfo {
  exitCode: number | null;
  signal: string | null;
  timedOut: boolean;
}

/**
 * 等待子进程退出。超时时调用一次 onTimeout 并标记 timedOut；
 * 之后最多再等 2s 等 close/exit，超过则强制以已知信息 resolve。
 */
export function waitForExit(
  child: ChildProcess,
  timeoutMs: number,
  onTimeout: () => void | Promise<void>,
): Promise<ExitInfo> {
  return new Promise((resolve) => {
    let exitCode: number | null = null;
    let signal: string | null = null;
    let timedOut = false;
    let done = false;
    let timer: NodeJS.Timeout | undefined;
    let graceTimer: NodeJS.Timeout | undefined;

    const finish = (): void => {
      if (done) return;
      done = true;
      if (timer !== undefined) clearTimeout(timer);
      if (graceTimer !== undefined) clearTimeout(graceTimer);
      resolve({ exitCode, signal, timedOut });
    };

    child.on('exit', (code, sig) => {
      exitCode = code;
      signal = sig;
      if (timedOut) finish();
    });
    child.on('close', (code, sig) => {
      if (!timedOut) {
        exitCode = code;
        signal = sig;
      }
      finish();
    });
    child.on('error', finish);

    timer = setTimeout(() => {
      timer = undefined;
      if (done) return;
      timedOut = true;
      try {
        const r = onTimeout();
        if (r instanceof Promise) r.catch(() => undefined);
      } catch {
        // onTimeout 失败不影响等待
      }
      graceTimer = setTimeout(finish, EXIT_GRACE_MS);
    }, timeoutMs);
  });
}

// ---------- 杀进程树 ----------

/** 杀掉进程树。进程已不存在或任何错误都吞掉，不抛。 */
export async function killTree(pid: number, toolPath: string): Promise<void> {
  if (IS_WIN) {
    await new Promise<void>((resolve) => {
      let settled = false;
      const done = (): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve();
      };
      const timer = setTimeout(done, KILL_WAIT_MS);
      try {
        const k = spawn(toolPath, ['/PID', String(pid), '/T', '/F'], {
          shell: false,
          windowsHide: true,
          stdio: 'ignore',
        });
        k.on('error', done);
        k.on('close', done);
      } catch {
        done();
      }
    });
    return;
  }
  try {
    process.kill(-pid, 'SIGKILL');
    return;
  } catch {
    // 不是进程组或已不存在，回退到单进程
  }
  try {
    process.kill(pid, 'SIGKILL');
  } catch {
    // ESRCH 等：视为成功
  }
}

// ---------- spawn 封装 ----------

/** 为 displayCommand 做安全拼接：含空白、引号或为空的元素用单引号包裹。 */
function quoteArg(s: string): string {
  if (s.length > 0 && !/[\s'"]/.test(s)) return s;
  return shSingleQuote(s);
}

export async function spawnCapture(input: {
  file: string;
  argv: readonly string[];
  env: NodeJS.ProcessEnv;
  timeoutMs: number;
  maxOutputBytes: number;
  cwd?: string;
  stdin?: 'ignore' | 'pipe';
  /** 有值时以 pipe 打开 stdin，写入后关闭；写入错误（如 EPIPE）被吞掉。 */
  stdinData?: string | Buffer;
}): Promise<RunResult> {
  const started = Date.now();
  const fullArgv = [input.file, ...input.argv];
  const displayCommand = fullArgv.map(quoteArg).join(' ');

  let taskkillPath = 'taskkill';
  if (IS_WIN) {
    try {
      taskkillPath = await resolveToolBinary('taskkill');
    } catch {
      taskkillPath = 'taskkill';
    }
  }

  const stdinMode = input.stdinData !== undefined ? 'pipe' : (input.stdin ?? 'ignore');
  const child = spawn(input.file, [...input.argv], {
    shell: false,
    windowsHide: true,
    env: input.env,
    cwd: input.cwd,
    stdio: [stdinMode, 'pipe', 'pipe'],
  });
  const untrack = trackChild(child);

  let spawnError: { code: string; message: string } | undefined;
  child.on('error', (err: NodeJS.ErrnoException) => {
    spawnError = { code: err.code ?? 'SPAWN_ERROR', message: err.message };
  });

  let stdoutBytes = 0;
  let stderrBytes = 0;
  const outP = child.stdout
    ? captureStream(child.stdout, input.maxOutputBytes, { onBytes: (n) => (stdoutBytes = n) })
    : Promise.resolve({ text: '', truncated: false });
  const errP = child.stderr
    ? captureStream(child.stderr, input.maxOutputBytes, { onBytes: (n) => (stderrBytes = n) })
    : Promise.resolve({ text: '', truncated: false });

  if (input.stdinData !== undefined) {
    // 子进程提前退出时写入会触发 EPIPE；吞掉，结果由 exitCode/spawnError 表达。
    child.stdin?.on('error', () => undefined);
    child.stdin?.end(input.stdinData);
  }

  const exit = await waitForExit(child, input.timeoutMs, () =>
    child.pid !== undefined ? killTree(child.pid, taskkillPath) : undefined,
  );
  untrack();

  // 超时/被杀后，流可能被孙进程占用：最多再等 2s
  const settle = Promise.all([outP, errP]);
  const streams = exit.timedOut
    ? await Promise.race([settle, new Promise<null>((r) => setTimeout(() => r(null), EXIT_GRACE_MS))])
    : await settle;
  const [out, err] = streams ?? [
    { text: '', truncated: false },
    { text: '', truncated: false },
  ];

  const result: RunResult = {
    argv: fullArgv,
    displayCommand,
    exitCode: exit.exitCode,
    signal: exit.signal,
    stdout: out.text,
    stderr: err.text,
    stdoutBytes,
    stderrBytes,
    stdoutTruncated: out.truncated,
    stderrTruncated: err.truncated,
    timedOut: exit.timedOut,
    durationMs: Date.now() - started,
  };
  if (spawnError !== undefined) result.spawnError = spawnError;
  return result;
}

/** 运行 ssh；不因非零退出码抛错，spawn 失败放在 spawnError。 */
export async function runSsh(input: {
  argv: readonly string[];
  timeoutMs: number;
  maxOutputBytes: number;
  env: NodeJS.ProcessEnv;
  cwd?: string;
  stdinData?: string | Buffer;
  label: string;
}): Promise<RunResult> {
  const { path: sshPath } = await resolveSshBinary();
  return spawnCapture({
    file: sshPath,
    argv: input.argv,
    env: input.env,
    timeoutMs: input.timeoutMs,
    maxOutputBytes: input.maxOutputBytes,
    cwd: input.cwd,
    ...(input.stdinData !== undefined ? { stdinData: input.stdinData } : {}),
  });
}
