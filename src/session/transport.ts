import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { buildSshArgv } from '../policy/argv.js';
import { encodeScript } from '../policy/remote-command.js';
import { buildSessionBootstrap } from '../policy/session.js';
import { resolveSshBinary, resolveToolBinary } from '../ssh/binary.js';
import { buildChildEnv } from '../ssh/env.js';
import { killTree, trackChild } from '../ssh/runner.js';
import type { EffectiveHost, Logger } from '../types.js';
import {
  CLOSE_GRACE_MS,
  LOCAL_STDERR_BYTES,
  PRE_RDY_DIAGNOSTIC_BYTES,
} from './constants.js';
import { createFrameParser, encodeCloseLine } from './frame.js';
import type { FrameEvent, FrameParseErrorCode, FrameParseResult } from './types.js';

const IS_WIN = process.platform === 'win32';
const KILL_SETTLE_MS = 1000;

/** 测试用：直接 spawn 本地 bash（`bash --noprofile --norc`）替代 ssh。 */
export interface SessionSpawnOverride {
  file: string;
  argv: readonly string[];
}

/** 握手阶段失败的事实；工具层据此生成 ToolError（不包含命令或 env 值）。 */
export interface SessionStartFacts {
  code: string;
  pre_rdy?: string;
  stderr?: string;
  exit_code?: number | null;
  signal?: string | null;
  parse_error?: string;
}

/** 会话启动失败（RDY 之前）。 */
export class SessionStartError extends Error {
  readonly code: string;
  readonly facts: SessionStartFacts;

  constructor(message: string, facts: SessionStartFacts) {
    super(message);
    this.name = 'SessionStartError';
    this.code = facts.code;
    this.facts = facts;
  }
}

/** 会话传输层向会话状态机上报的事件。 */
export type TransportEvent =
  | FrameEvent
  | { type: 'parse_error'; error: FrameParseErrorCode }
  | { type: 'exit'; exit_code: number | null; signal: string | null };

export interface TransportCloseFacts {
  exit_code: number | null;
  signal: string | null;
  /** 是否在宽限期内通过 Q/EOF 优雅退出。 */
  graceful: boolean;
  /** 是否需要本地强杀进程树。 */
  killed: boolean;
}

export interface SessionTransport {
  /** 只能 attach 一次；attach 之前的 RDY 后事件被缓冲。 */
  attach(handler: (event: TransportEvent) => void): void;
  /** 写入一行协议文本（自动补齐一个换行）；失败即 reject。 */
  writeLine(line: string): Promise<void>;
  /** 幂等关闭：Q + EOF，宽限期后杀进程树；永不 reject。 */
  close(): Promise<TransportCloseFacts>;
  /** 子进程退出（永不 reject）；正常 close 也会 resolve。 */
  readonly exited: Promise<{ exit_code: number | null; signal: string | null }>;
  /** RDY 之前的远端输出尾部（诊断用）。 */
  readonly preRdyDiagnostic: string;
  /** 本地 ssh stderr 尾部（诊断用）。 */
  readonly stderrDiagnostic: string;
}

export interface OpenSessionTransportOptions {
  host: EffectiveHost;
  /** 目标标识（user@host:port）；仅用于日志，argv 由 host 生成。 */
  destination?: string;
  knownHostsFile: string;
  nonce: string;
  cwdExpr: string;
  envLines: readonly string[];
  handshakeTimeoutMs: number;
  log: Logger;
  /** 仅测试用：替换 ssh 为本地 bash。 */
  spawnOverride?: SessionSpawnOverride;
  /** 测试用：覆盖关闭宽限期。 */
  closeGraceMs?: number;
}

/** 固定尾部缓冲：只保留最后 cap 字节。 */
class TailBuffer {
  private chunks: Buffer[] = [];
  private len = 0;

  constructor(private readonly cap: number) {}

  push(chunk: Buffer): void {
    if (chunk.length === 0) return;
    this.chunks.push(chunk);
    this.len += chunk.length;
    if (this.len > this.cap * 2) {
      const merged = Buffer.concat(this.chunks, this.len);
      this.chunks = [merged.subarray(merged.length - this.cap)];
      this.len = this.cap;
    }
  }

  text(): string {
    const merged = Buffer.concat(this.chunks, this.len);
    return merged.subarray(Math.max(0, merged.length - this.cap)).toString('utf8');
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    timer.unref?.();
  });
}

async function resolveTaskkill(): Promise<string> {
  if (!IS_WIN) return 'taskkill';
  try {
    return await resolveToolBinary('taskkill');
  } catch {
    return 'taskkill';
  }
}

function diagnosticFacts(pre: TailBuffer, stderr: TailBuffer): Pick<SessionStartFacts, 'pre_rdy' | 'stderr'> {
  const preText = pre.text();
  const errText = stderr.text();
  return {
    ...(preText.length > 0 ? { pre_rdy: preText } : {}),
    ...(errText.length > 0 ? { stderr: errText } : {}),
  };
}

/**
 * 建立一条持久会话传输：ssh <host> 'bash --noprofile --norc'，把 bootstrap
 * 脚本写到 stdin，随后等待 RDY。握手成功后返回可 attach 的传输对象。
 *
 * 失败（握手超时、RDY 前退出、协议错误、写入失败）一律 reject 一个
 * SessionStartError，并杀掉进程树、从全局登记中注销。
 */
export function openSessionTransport(opts: OpenSessionTransportOptions): Promise<SessionTransport> {
  return openSessionTransportImpl(opts);
}

async function openSessionTransportImpl(opts: OpenSessionTransportOptions): Promise<SessionTransport> {
  const {
    host,
    knownHostsFile,
    nonce,
    cwdExpr,
    envLines,
    handshakeTimeoutMs,
    log,
    spawnOverride,
    closeGraceMs = CLOSE_GRACE_MS,
  } = opts;

  if (typeof handshakeTimeoutMs !== 'number' || !Number.isFinite(handshakeTimeoutMs) || handshakeTimeoutMs <= 0) {
    throw new TypeError('handshakeTimeoutMs must be a positive number');
  }

  let file: string;
  let argv: string[];
  if (spawnOverride !== undefined) {
    file = spawnOverride.file;
    argv = [...spawnOverride.argv];
  } else {
    const built = buildSshArgv({
      host,
      knownHostsFile,
      remoteCommand: 'bash --noprofile --norc',
      mode: 'strict',
    });
    argv = built.argv;
    file = (await resolveSshBinary()).path;
  }

  // 交付方式：把整段 bootstrap 编码成 payload，用一行 `eval` 交给远端 bash。
  // 不能逐行把脚本写进 bash 的 stdin——bash 解析脚本时会预读，脚本末尾的
  // `exec 1>&3 2>&3` 会被 while-read 循环当成协议数据（产生假的 B:exec 帧）。
  // 单行 eval 让 bash 解析器只消费这一行，随后 stdin 完全留给协议行。
  const bootstrapScript = buildSessionBootstrap({ nonce, cwdExpr, envLines }).join('\n');
  const bootstrapLine = `builtin eval "$(builtin printf %b '${encodeScript(bootstrapScript)}')"`;
  const taskkillPath = await resolveTaskkill();

  return await new Promise<SessionTransport>((resolveTransport, rejectTransport) => {
    let child: ChildProcess;
    try {
      child = spawn(file, argv, {
        shell: false,
        windowsHide: true,
        env: buildChildEnv(),
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch (err) {
      rejectTransport(
        new SessionStartError('failed to spawn session transport', {
          code: 'session_spawn_failed',
          stderr: err instanceof Error ? err.message : String(err),
        }),
      );
      return;
    }

    const stdout = child.stdout;
    const stderr = child.stderr;
    const stdin = child.stdin;
    if (stdout === null || stderr === null || stdin === null) {
      rejectTransport(
        new SessionStartError('session transport did not expose stdio pipes', {
          code: 'session_spawn_failed',
        }),
      );
      return;
    }
    const stdinPipe = stdin;

    const untrack = trackChild(child);
    const parser = createFrameParser(nonce);
    const preRdy = new TailBuffer(PRE_RDY_DIAGNOSTIC_BYTES);
    const localStderr = new TailBuffer(LOCAL_STDERR_BYTES);

    let started = false;
    let ready = false;
    let shuttingDown = false;
    let exited = false;
    let exitCode: number | null = null;
    let signal: string | null = null;
    let stdinBroken = false;
    let attached: ((event: TransportEvent) => void) | undefined;
    let buffered: TransportEvent[] = [];
    let handshakeTimer: NodeJS.Timeout | undefined;
    let closePromise: Promise<TransportCloseFacts> | undefined;
    let resolveExited: (value: { exit_code: number | null; signal: string | null }) => void = () => undefined;

    const exitedPromise = new Promise<{ exit_code: number | null; signal: string | null }>(
      (resolve) => {
        resolveExited = resolve;
      },
    );

    const dispatch = (event: TransportEvent): void => {
      if (shuttingDown) return;
      if (attached === undefined) {
        buffered.push(event);
        return;
      }
      try {
        attached(event);
      } catch (err) {
        try {
          log.warn({ err: err instanceof Error ? err.message : String(err) }, 'session transport handler failed');
        } catch {
          // 日志失败不影响数据流
        }
      }
    };

    const abort = async (): Promise<void> => {
      untrack();
      try {
        stdin.destroy();
      } catch {
        // 已销毁
      }
      if (child.pid !== undefined) await killTree(child.pid, taskkillPath);
    };

    const failStart = (error: SessionStartError): void => {
      if (started) return;
      started = true;
      shuttingDown = true;
      if (handshakeTimer !== undefined) {
        clearTimeout(handshakeTimer);
        handshakeTimer = undefined;
      }
      void abort();
      rejectTransport(error);
    };

    const markExited = (code: number | null, sig: string | null, spawnError?: unknown): void => {
      if (exited) return;
      exited = true;
      exitCode = code;
      signal = sig;
      resolveExited({ exit_code: code, signal: sig });
      if (!ready) {
        const error = new SessionStartError(
          spawnError !== undefined
            ? 'session transport failed to start'
            : `session transport exited before RDY (exit=${String(code)}, signal=${String(sig)})`,
          {
            code: spawnError !== undefined ? 'session_spawn_failed' : 'session_exited_early',
            exit_code: code,
            signal: sig,
            ...diagnosticFacts(preRdy, localStderr),
            ...(spawnError !== undefined
              ? { stderr: `${localStderr.text()}\n${String((spawnError as { message?: unknown }).message ?? spawnError)}`.trim() }
              : {}),
          },
        );
        failStart(error);
        return;
      }
      dispatch({ type: 'exit', exit_code: code, signal: sig });
    };

    const handleEvent = (event: FrameEvent): void => {
      if (!ready) {
        if (event.type === 'data') {
          preRdy.push(event.buf);
          return;
        }
        if (event.frame.type === 'RDY') {
          ready = true;
          started = true;
          if (handshakeTimer !== undefined) {
            clearTimeout(handshakeTimer);
            handshakeTimer = undefined;
          }
          try {
            log.debug(
              { destination: opts.destination, pid: child.pid },
              'session transport ready',
            );
          } catch {
            // 日志失败不影响握手
          }
          resolveTransport(transport);
          return;
        }
        failStart(
          new SessionStartError('received a control frame before RDY', {
            code: 'session_protocol_error',
            ...diagnosticFacts(preRdy, localStderr),
          }),
        );
        return;
      }
      dispatch(event);
    };

    const writeRaw = async (text: string): Promise<void> => {
      if (stdinBroken || stdin.destroyed || stdin.writableEnded) {
        throw new Error('session transport stdin is closed');
      }
      try {
        const ok = stdin.write(text);
        if (!ok) {
          await Promise.race([
            once(stdin, 'drain').then(() => undefined),
            exitedPromise.then(() => {
              throw new Error('session transport exited while writing');
            }),
          ]);
        }
      } catch (err) {
        stdinBroken = true;
        throw err instanceof Error ? err : new Error(String(err));
      }
    };

    const transport: SessionTransport = {
      attach(handler: (event: TransportEvent) => void): void {
        if (attached !== undefined) throw new Error('session transport is already attached');
        attached = handler;
        const queued = buffered;
        buffered = [];
        for (const event of queued) handler(event);
      },
      async writeLine(line: string): Promise<void> {
        if (typeof line !== 'string') throw new TypeError('writeLine requires a string');
        const body = line.endsWith('\n') ? line.slice(0, -1) : line;
        if (body.includes('\n')) throw new Error('writeLine accepts exactly one line');
        await writeRaw(`${body}\n`);
      },
      close(): Promise<TransportCloseFacts> {
        closePromise ??= performClose();
        return closePromise;
      },
      get exited() {
        return exitedPromise;
      },
      get preRdyDiagnostic(): string {
        return preRdy.text();
      },
      get stderrDiagnostic(): string {
        return localStderr.text();
      },
    };

    async function performClose(): Promise<TransportCloseFacts> {
      shuttingDown = true;
      let graceful = false;
      let killed = false;
      try {
        if (exited) {
          // close() 之前子进程已经退出：没有写入 Q，也不算优雅关闭；
          // exit_code/signal 保持 markExited 记录的真实值。
          graceful = false;
        } else {
          let closeWritten = false;
          try {
            await writeRaw(encodeCloseLine());
            closeWritten = true;
          } catch {
            // 子进程可能已经退出；继续等待/强杀
          }
          try {
            stdinPipe.end();
          } catch {
            // 已关闭
          }
          graceful =
            closeWritten &&
            (await Promise.race([
              exitedPromise.then(() => true),
              delay(closeGraceMs).then(() => false),
            ]));
        }
        if (!exited) {
          killed = true;
          untrack();
          if (child.pid !== undefined) await killTree(child.pid, taskkillPath);
          await Promise.race([exitedPromise, delay(KILL_SETTLE_MS)]);
        }
      } catch {
        // close 永不 reject
      }
      untrack();
      return { exit_code: exitCode, signal, graceful, killed };
    }

    child.on('error', (err: Error) => {
      markExited(null, null, err);
    });
    child.on('close', (code, sig) => {
      markExited(code, sig);
    });

    const handleParseResult = (result: FrameParseResult): void => {
      for (const event of result.events) {
        if (shuttingDown) return;
        handleEvent(event);
      }
      if (result.error !== undefined) {
        if (!ready) {
          failStart(
            new SessionStartError(`frame parser failed during handshake: ${result.error}`, {
              code: 'session_protocol_error',
              parse_error: result.error,
              ...diagnosticFacts(preRdy, localStderr),
            }),
          );
        } else {
          dispatch({ type: 'parse_error', error: result.error });
        }
      }
    };

    stdout.on('data', (chunk: Buffer) => {
      if (shuttingDown) return;
      handleParseResult(parser.push(chunk));
    });
    // EOF：解析器可能还握着不完整的标记前缀（例如远端在输出中途退出）。
    // 这些字节是普通数据，必须按当前阶段交付（握手前进诊断，握手后交给 handler）。
    stdout.on('end', () => {
      if (shuttingDown) return;
      handleParseResult({ events: parser.flush() });
    });
    stdout.on('error', () => undefined);

    stderr.on('data', (chunk: Buffer) => {
      localStderr.push(chunk);
    });
    stderr.on('error', () => undefined);
    stdin.on('error', () => {
      stdinBroken = true;
    });

    handshakeTimer = setTimeout(() => {
      handshakeTimer = undefined;
      failStart(
        new SessionStartError(`timed out after ${handshakeTimeoutMs}ms waiting for RDY`, {
          code: 'session_handshake_timeout',
          ...diagnosticFacts(preRdy, localStderr),
        }),
      );
    }, handshakeTimeoutMs);
    handshakeTimer.unref?.();

    void (async () => {
      try {
        await writeRaw(`${bootstrapLine}\n`);
      } catch (err) {
        failStart(
          new SessionStartError('failed to write session bootstrap', {
            code: 'session_write_failed',
            ...diagnosticFacts(preRdy, localStderr),
            ...(err instanceof Error ? { stderr: err.message } : {}),
          }),
        );
      }
    })();
  });
}
