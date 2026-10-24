import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';

// 协议级验收：用子进程直接驱动 dist/cli.js 的 JSON-RPC over stdio。
// 不依赖 MCP client 包；stdout 必须是纯 NDJSON，任何非 JSON 行都视为违规。

const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const CLI_ENTRY = 'dist/cli.js';

const TEST_TIMEOUT_MS = 15_000;
const SEND_TIMEOUT_MS = 10_000;
const EXIT_TIMEOUT_MS = 3_000;
/** 产品指标保持 1000ms；用 best-of-3 吸收 Windows 冷启动与杀软扫描噪声。 */
const COLD_START_LIMIT_MS = 1_000;
const COLD_START_ATTEMPTS = 3;

const INITIALIZE_PARAMS = {
  protocolVersion: '2026-07-28',
  capabilities: {},
  clientInfo: { name: 'remote-mcp-protocol-test', version: '0' },
} as const;

interface JsonRpcMessage {
  jsonrpc?: string;
  id?: number | string;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: { code?: number; message?: string; data?: unknown };
}

interface ToolCallResult {
  content?: Array<{ type?: string; text?: string }>;
  isError?: boolean;
  structuredContent?: unknown;
}

interface ToolAnnotations {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

interface ToolsListResult {
  tools?: Array<{ name?: string; annotations?: ToolAnnotations }>;
}

interface ExitInfo {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  forced: boolean;
  elapsedMs: number;
}

interface StartServerOptions {
  args?: string[];
  env?: NodeJS.ProcessEnv;
  /** 从继承的环境变量中删除的键（大小写不敏感，Windows 语义）。 */
  unsetEnv?: string[];
}

interface ServerHarness {
  child: ChildProcessWithoutNullStreams;
  /** stdout 的每一行（已去掉行尾 \r）。 */
  readonly rawLines: string[];
  /** 无法 JSON.parse 的 stdout 行：出现任意一条即为违规。 */
  readonly nonJsonLines: string[];
  /** 成功解析出的 JSON-RPC 消息（响应与通知）。 */
  readonly messages: JsonRpcMessage[];
  stderrText(): string;
  /** 从 spawn 到 initialize 响应被读取的毫秒数；未收到时为 undefined。 */
  coldStartMs(): number | undefined;
  send(method: string, params: unknown, id: number): Promise<JsonRpcMessage>;
  notify(method: string, params?: unknown): void;
  close(): Promise<ExitInfo>;
  dispose(): void;
}

const activeHarnesses = new Set<ServerHarness>();
const tempDirs = new Set<string>();

async function makeTempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'remote-mcp-protocol-'));
  tempDirs.add(dir);
  return dir;
}

/** 合并环境变量后按需删除键；保证不读取真实 ~/.remote-mcp。 */
function buildEnv(overrides: NodeJS.ProcessEnv | undefined, unset: string[] | undefined): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, ...(overrides ?? {}) };
  const upper = new Set((unset ?? []).map((k) => k.toUpperCase()));
  for (const key of Object.keys(env)) {
    if (upper.has(key.toUpperCase())) delete env[key];
  }
  return env;
}

function startServer(opts: StartServerOptions = {}): ServerHarness {
  const env = buildEnv(opts.env, opts.unsetEnv);
  const argv = [CLI_ENTRY, ...(opts.args ?? [])];
  const spawnedAt = performance.now();

  const child = spawn(process.execPath, argv, {
    cwd: PROJECT_ROOT,
    env,
    stdio: ['pipe', 'pipe', 'pipe'],
    shell: false,
    windowsHide: true,
  }) as unknown as ChildProcessWithoutNullStreams;

  const rawLines: string[] = [];
  const nonJsonLines: string[] = [];
  const messages: JsonRpcMessage[] = [];
  let stderr = '';
  let stdoutBuffer = '';
  let coldStart: number | undefined;
  let exitInfo: ExitInfo | undefined;
  let closePromise: Promise<ExitInfo> | undefined;

  interface Pending {
    method: string;
    resolve: (msg: JsonRpcMessage) => void;
    reject: (err: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }
  const pending = new Map<number | string, Pending>();

  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk: string) => {
    stderr += chunk;
  });
  // 父进程提前关闭 stdin 时可能出现 EPIPE；不视为测试失败，由 close/exit 断言覆盖。
  child.stdin.on('error', () => undefined);

  function settle(msg: JsonRpcMessage, receivedAt: number): void {
    if (msg.id === undefined || msg.id === null) return;
    const entry = pending.get(msg.id);
    if (entry === undefined) return;
    pending.delete(msg.id);
    clearTimeout(entry.timer);
    if (entry.method === 'initialize' && coldStart === undefined) {
      coldStart = receivedAt - spawnedAt;
    }
    entry.resolve(msg);
  }

  function handleLine(rawLine: string, receivedAt: number): void {
    const line = rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine;
    rawLines.push(line);

    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      nonJsonLines.push(line);
      return;
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      nonJsonLines.push(line);
      return;
    }
    const msg = parsed as JsonRpcMessage;
    messages.push(msg);
    settle(msg, receivedAt);
  }

  child.stdout.on('data', (chunk: string) => {
    stdoutBuffer += chunk;
    let newline: number;
    while ((newline = stdoutBuffer.indexOf('\n')) !== -1) {
      const line = stdoutBuffer.slice(0, newline);
      stdoutBuffer = stdoutBuffer.slice(newline + 1);
      handleLine(line, performance.now());
    }
  });
  child.stdout.on('end', () => {
    if (stdoutBuffer.length > 0) {
      const rest = stdoutBuffer;
      stdoutBuffer = '';
      handleLine(rest, performance.now());
    }
  });

  child.on('exit', (code, signal) => {
    for (const [id, entry] of pending) {
      pending.delete(id);
      clearTimeout(entry.timer);
      entry.reject(
        new Error(
          `server exited (code=${String(code)}, signal=${String(signal)}) before responding to ` +
            `${entry.method} id=${String(id)}; stderr:\n${stderr.slice(-2000)}`,
        ),
      );
    }
    exitInfo = { exitCode: code, signal, forced: false, elapsedMs: 0 };
  });

  child.on('error', (err) => {
    for (const [id, entry] of pending) {
      pending.delete(id);
      clearTimeout(entry.timer);
      entry.reject(new Error(`server process error before responding to ${entry.method} id=${String(id)}: ${err.message}`));
    }
  });

  function waitForExit(ms: number): Promise<{ exitCode: number | null; signal: NodeJS.Signals | null } | undefined> {
    if (child.exitCode !== null || child.signalCode !== null) {
      return Promise.resolve({ exitCode: child.exitCode, signal: child.signalCode });
    }
    return new Promise((resolve) => {
      const onExit = (code: number | null, signal: NodeJS.Signals | null): void => {
        clearTimeout(timer);
        resolve({ exitCode: code, signal });
      };
      const timer = setTimeout(() => {
        child.removeListener('exit', onExit);
        resolve(undefined);
      }, ms);
      child.once('exit', onExit);
    });
  }

  function writeLine(payload: unknown): void {
    if (child.stdin.writableEnded || child.stdin.destroyed) {
      throw new Error('cannot write to server: stdin is closed');
    }
    child.stdin.write(`${JSON.stringify(payload)}\n`);
  }

  const harness: ServerHarness = {
    child,
    rawLines,
    nonJsonLines,
    messages,
    stderrText: () => stderr,
    coldStartMs: () => coldStart,
    send(method: string, params: unknown, id: number): Promise<JsonRpcMessage> {
      const response = new Promise<JsonRpcMessage>((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(
            new Error(
              `timed out after ${SEND_TIMEOUT_MS}ms waiting for ${method} id=${id}; stderr:\n${stderr.slice(-2000)}`,
            ),
          );
        }, SEND_TIMEOUT_MS);
        pending.set(id, { method, resolve, reject, timer });
      });
      writeLine({ jsonrpc: '2.0', id, method, ...(params !== undefined ? { params } : {}) });
      return response;
    },
    notify(method: string, params?: unknown): void {
      writeLine({ jsonrpc: '2.0', method, ...(params !== undefined ? { params } : {}) });
    },
    close(): Promise<ExitInfo> {
      if (closePromise !== undefined) return closePromise;
      const closeStartedAt = performance.now();
      closePromise = (async (): Promise<ExitInfo> => {
        const waited = waitForExit(EXIT_TIMEOUT_MS);
        try {
          child.stdin.end();
        } catch {
          // stdin 已损坏/已关闭时继续等待进程退出。
        }
        let info = await waited;
        let forced = false;
        if (info === undefined) {
          try {
            child.kill('SIGKILL');
          } catch {
            // 进程可能刚好退出。
          }
          const killed = await waitForExit(1_500);
          info = killed ?? { exitCode: child.exitCode, signal: child.signalCode };
          forced = true;
        }
        const result: ExitInfo = {
          exitCode: info.exitCode,
          signal: info.signal,
          forced,
          elapsedMs: performance.now() - closeStartedAt,
        };
        exitInfo = result;
        activeHarnesses.delete(harness);
        try {
          child.stdin.destroy();
          child.stdout.destroy();
          child.stderr.destroy();
        } catch {
          // 流可能已销毁。
        }
        return result;
      })();
      return closePromise;
    },
    dispose(): void {
      activeHarnesses.delete(harness);
      if (child.exitCode === null && child.signalCode === null) {
        try {
          child.kill('SIGKILL');
        } catch {
          // 忽略。
        }
      }
      for (const stream of [child.stdin, child.stdout, child.stderr]) {
        try {
          stream.destroy();
        } catch {
          // 忽略。
        }
      }
    },
  };

  void exitInfo;
  activeHarnesses.add(harness);
  return harness;
}

function toolResultText(result: ToolCallResult): string {
  return (result.content ?? [])
    .filter((item) => item.type === 'text' && typeof item.text === 'string')
    .map((item) => item.text as string)
    .join('\n');
}

async function callHostList(harness: ServerHarness, id: number): Promise<ToolCallResult> {
  const response = await harness.send('tools/call', { name: 'host_list', arguments: {} }, id);
  expect(response.error, `tools/call host_list returned JSON-RPC error: ${JSON.stringify(response.error)}`).toBeUndefined();
  expect(response.result, 'tools/call host_list returned no result').toBeDefined();
  return response.result as ToolCallResult;
}

async function assertToolsListed(harness: ServerHarness, id: number): Promise<void> {
  const response = await harness.send('tools/list', {}, id);
  expect(response.error, `tools/list returned JSON-RPC error: ${JSON.stringify(response.error)}`).toBeUndefined();
  const result = response.result as ToolsListResult;
  const tools = result.tools ?? [];
  const names = tools.map((tool) => tool.name);
  for (const name of [
    'host_list',
    'host_check',
    'ssh_exec',
    'ssh_upload',
    'ssh_download',
    'ssh_read_file',
    'ssh_write_file',
    'session_start',
    'session_send',
    'session_close',
    'session_list',
  ]) {
    expect(names).toContain(name);
  }
  expect(names).toHaveLength(11);

  const annotationsOf = (name: string): ToolAnnotations | undefined =>
    tools.find((tool) => tool.name === name)?.annotations;

  expect(annotationsOf('ssh_exec')).toMatchObject({
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
  });
  for (const name of ['ssh_upload', 'ssh_download', 'ssh_write_file']) {
    expect(annotationsOf(name)).toEqual({
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    });
  }
  expect(annotationsOf('ssh_read_file')).toEqual({
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  });

  expect(annotationsOf('session_start')).toEqual({
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: true,
  });
  expect(annotationsOf('session_send')).toEqual({
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: true,
  });
  expect(annotationsOf('session_close')).toEqual({
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: true,
    openWorldHint: true,
  });
  expect(annotationsOf('session_list')).toEqual({ readOnlyHint: true });
}

/** 单次 CLI 运行（不进入 MCP 会话），用于未知命令等场景。 */
function runCliOnce(args: string[]): Promise<{ exitCode: number | null; signal: NodeJS.Signals | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI_ENTRY, ...args], {
      cwd: PROJECT_ROOT,
      env: { ...process.env },
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false,
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk: string) => {
      stderr += chunk;
    });
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`CLI did not exit within ${TEST_TIMEOUT_MS}ms; stderr:\n${stderr.slice(-2000)}`));
    }, TEST_TIMEOUT_MS);
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('close', (exitCode, signal) => {
      clearTimeout(timer);
      resolve({ exitCode, signal, stdout, stderr });
    });
  });
}

afterEach(async () => {
  for (const harness of [...activeHarnesses]) harness.dispose();
  activeHarnesses.clear();
  for (const dir of tempDirs) {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }).catch(() => undefined);
  }
  tempDirs.clear();
});

describe('MCP protocol over stdio', () => {
  it(
    'initialize + tools/list works and cold start is under 1000ms (best of 3)',
    { timeout: 30_000 },
    async () => {
      const samples: number[] = [];

      for (let attempt = 0; attempt < COLD_START_ATTEMPTS; attempt++) {
        const home = await makeTempDir();
        const harness = startServer({
          env: {
            USERPROFILE: home,
            HOME: home,
            REMOTE_MCP_CONFIG: path.join(home, 'absent-config.yaml'),
          },
        });

        const initialize = await harness.send('initialize', INITIALIZE_PARAMS, 1);
        expect(
          initialize.error,
          `initialize returned JSON-RPC error: ${JSON.stringify(initialize.error)}`,
        ).toBeUndefined();
        // 忽略协议版本协商差异，只要求有 result（且服务器身份正确）。
        expect(initialize.result).toBeDefined();
        const serverInfo = (initialize.result as { serverInfo?: { name?: string } }).serverInfo;
        expect(serverInfo?.name).toBe('remote-mcp');

        const coldStart = harness.coldStartMs();
        expect(coldStart, 'cold start was not recorded').toBeDefined();
        samples.push(coldStart as number);

        harness.notify('notifications/initialized');
        await assertToolsListed(harness, 2);

        const exit = await harness.close();
        expect(exit.forced, 'server had to be killed instead of exiting on EOF').toBe(false);
        expect(exit.exitCode).toBe(0);
      }

      const best = Math.min(...samples);
      console.log(
        `[cold-start] attempts=[${samples.map((v) => v.toFixed(1)).join(', ')}]ms; ` +
          `best=${best.toFixed(1)}ms (limit ${COLD_START_LIMIT_MS}ms)`,
      );
      expect(samples).toHaveLength(COLD_START_ATTEMPTS);
      expect(best).toBeLessThan(COLD_START_LIMIT_MS);
    },
  );

  it(
    'stdout stays pure NDJSON for the whole session',
    { timeout: TEST_TIMEOUT_MS },
    async () => {
      const home = await makeTempDir();
      const harness = startServer({
        env: {
          USERPROFILE: home,
          HOME: home,
          REMOTE_MCP_CONFIG: path.join(home, 'absent-config.yaml'),
        },
      });

      const initialize = await harness.send('initialize', INITIALIZE_PARAMS, 1);
      expect(initialize.result).toBeDefined();
      harness.notify('notifications/initialized');
      await assertToolsListed(harness, 2);

      await harness.close();

      expect(harness.rawLines.length).toBeGreaterThanOrEqual(2);
      expect(
        harness.nonJsonLines,
        `stdout contained non-JSON lines:\n${harness.nonJsonLines.join('\n')}`,
      ).toEqual([]);
      for (const line of harness.rawLines) {
        expect(() => JSON.parse(line)).not.toThrow();
      }
      // 日志必须走 stderr（本会话至少会有一条 serving 日志）。
      expect(harness.stderrText()).toMatch(/serving MCP over stdio/);
    },
  );

  it(
    'stays connectable when config is missing; host_list reports a Policy error',
    { timeout: TEST_TIMEOUT_MS },
    async () => {
      const emptyHome = await makeTempDir();
      const harness = startServer({
        env: { USERPROFILE: emptyHome, HOME: emptyHome },
        unsetEnv: ['REMOTE_MCP_CONFIG'],
      });

      const initialize = await harness.send('initialize', INITIALIZE_PARAMS, 1);
      expect(initialize.error, `initialize failed: ${JSON.stringify(initialize.error)}`).toBeUndefined();
      expect(initialize.result).toBeDefined();
      harness.notify('notifications/initialized');
      await assertToolsListed(harness, 2);

      const result = await callHostList(harness, 3);
      expect(result.isError).toBe(true);
      const text = toolResultText(result);
      expect(text).toMatch(/\[Policy\]/);
      expect(text).toMatch(/config_(not_found|io)/);
      expect(text).toMatch(/config file not found/i);
      // 错误里必须带上实际解析到的路径，便于用户定位。
      expect(text).toContain(emptyHome);

      const exit = await harness.close();
      expect(exit.exitCode).toBe(0);
    },
  );

  it(
    'stays connectable when config is corrupt; host_list reports a parse/schema error',
    { timeout: TEST_TIMEOUT_MS },
    async () => {
      const dir = await makeTempDir();
      const configPath = path.join(dir, 'bad.yaml');
      await writeFile(configPath, 'hosts: [', 'utf8');

      const harness = startServer({
        args: ['--config', configPath],
        env: { USERPROFILE: dir, HOME: dir },
        unsetEnv: ['REMOTE_MCP_CONFIG'],
      });

      const initialize = await harness.send('initialize', INITIALIZE_PARAMS, 1);
      expect(initialize.error, `initialize failed: ${JSON.stringify(initialize.error)}`).toBeUndefined();
      expect(initialize.result).toBeDefined();
      harness.notify('notifications/initialized');
      await assertToolsListed(harness, 2);

      const result = await callHostList(harness, 3);
      expect(result.isError).toBe(true);
      const text = toolResultText(result);
      expect(text).toMatch(/\[Policy\]/);
      // YAML 语法错误 -> config_parse；若解析器行为变化落到 schema 也接受。
      expect(text).toMatch(/config_(parse|schema)/);
      expect(text).toMatch(/YAML syntax error|invalid config/i);
      expect(text).toContain(configPath);

      const exit = await harness.close();
      expect(exit.exitCode).toBe(0);
    },
  );

  it(
    'exits with code 0 within 3s after stdin closes',
    { timeout: TEST_TIMEOUT_MS },
    async () => {
      const home = await makeTempDir();
      const harness = startServer({
        env: {
          USERPROFILE: home,
          HOME: home,
          REMOTE_MCP_CONFIG: path.join(home, 'absent-config.yaml'),
        },
      });

      const initialize = await harness.send('initialize', INITIALIZE_PARAMS, 1);
      expect(initialize.result).toBeDefined();

      const exit = await harness.close();
      if (exit.exitCode !== 0 || exit.forced) {
        console.log(
          `[shutdown] actual exitCode=${String(exit.exitCode)} signal=${String(exit.signal)} forced=${String(exit.forced)} elapsedMs=${exit.elapsedMs.toFixed(1)}`,
        );
      }
      expect(exit.forced, `server did not exit within ${EXIT_TIMEOUT_MS}ms after stdin end`).toBe(false);
      expect(exit.elapsedMs).toBeLessThan(EXIT_TIMEOUT_MS);
      // 正常关闭路径应返回 EXIT.ok（0）；平台差异导致其他值时保留实际值并在测试输出中打印。
      expect(exit.exitCode).toBe(0);
    },
  );

  it(
    'unknown command exits non-zero and prints usage to stderr',
    { timeout: TEST_TIMEOUT_MS },
    async () => {
      const result = await runCliOnce(['nonsense']);
      expect(result.exitCode).not.toBe(0);
      expect(result.exitCode).toBe(2);
      expect(result.stderr).toMatch(/unknown command: nonsense/);
      expect(result.stderr).toMatch(/用法|Usage/);
      expect(result.stdout).toBe('');
    },
  );
});
