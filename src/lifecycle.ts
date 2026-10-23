import { parseArgs } from 'node:util';
import { loadConfig } from './config/load.js';
import { resolvePaths } from './config/paths.js';
import { EXIT } from './constants.js';
import { ConfigError, UsageError } from './errors/classes.js';
import { createLogger, serializeError } from './log.js';
import { effectiveHost } from './policy/target.js';
import { killAllTrackedChildren } from './ssh/runner.js';
import { serve } from './server.js';
import { runTrustFlow } from './trust/flow.js';
import type { Logger } from './types.js';
import { VERSION } from './version.js';

export type CliCommand =
  | { kind: 'serve'; configPath?: string }
  | {
      kind: 'trust';
      alias: string;
      configPath?: string;
      rotate: boolean;
      fingerprint?: string;
      interactive: boolean;
    }
  | { kind: 'help' }
  | { kind: 'version' };

const FINGERPRINT_PREFIX = 'SHA256:';

/**
 * 解析命令行。无位置参数 -> serve；`trust <alias>` -> trust；--help/-h、--version/-v。
 * 未知选项、缺失参数或未知命令抛 UsageError。
 */
function parseRaw(argv: readonly string[]) {
  return parseArgs({
    args: [...argv],
    allowPositionals: true,
    strict: true,
    options: {
      config: { type: 'string' },
      rotate: { type: 'boolean' },
      fingerprint: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'v' },
    },
  });
}

export function parseCliArgs(argv: readonly string[]): CliCommand {
  let parsed: ReturnType<typeof parseRaw>;
  try {
    parsed = parseRaw(argv);
  } catch (cause) {
    throw new UsageError(cause instanceof Error ? cause.message : String(cause), { cause });
  }

  const { values, positionals } = parsed;
  if (values.help === true) return { kind: 'help' };
  if (values.version === true) return { kind: 'version' };

  const configPath = values.config;
  const fingerprint = values.fingerprint;
  if (fingerprint !== undefined && !fingerprint.startsWith(FINGERPRINT_PREFIX)) {
    throw new UsageError(`--fingerprint must start with "${FINGERPRINT_PREFIX}"`);
  }
  const [command, ...rest] = positionals;

  if (command === undefined) {
    if (values.rotate === true || fingerprint !== undefined) {
      throw new UsageError('--rotate and --fingerprint apply only to the trust command');
    }
    return configPath !== undefined ? { kind: 'serve', configPath } : { kind: 'serve' };
  }

  if (command === 'trust') {
    const alias = rest[0];
    if (alias === undefined || alias === '') {
      throw new UsageError('trust requires an alias: remote-mcp trust <alias>');
    }
    if (rest.length > 1) {
      throw new UsageError(`unexpected extra arguments for trust: ${rest.slice(1).join(' ')}`);
    }
    const cmd: CliCommand = {
      kind: 'trust',
      alias,
      rotate: values.rotate === true,
      interactive: fingerprint === undefined,
    };
    if (configPath !== undefined) cmd.configPath = configPath;
    if (fingerprint !== undefined) cmd.fingerprint = fingerprint;
    return cmd;
  }

  throw new UsageError(`unknown command: ${command}`);
}

const USAGE = `用法:
  remote-mcp [--config <path>]                 以 MCP stdio 模式运行服务器
  remote-mcp trust <alias> [选项]              信任某主机的 SSH 主机密钥
  remote-mcp --help | --version

全局选项:
  --config <path>                    指定配置文件（优先于环境变量 REMOTE_MCP_CONFIG）

trust 选项:
  --rotate                           允许替换已变化的已固定主机密钥
  --fingerprint <SHA256:...>         非交互确认：探测到的指纹必须与此完全一致

示例:
  remote-mcp trust web1                                交互确认（需输入 yes）
  remote-mcp trust web1 --fingerprint SHA256:xxxx      非交互确认（脚本/CI）
  remote-mcp trust web1 --rotate --fingerprint SHA256:xxxx

日志写入 stderr，级别由 REMOTE_MCP_LOG_LEVEL 控制（debug|info|warn|error）。
`;

export function printUsage(stream: NodeJS.WritableStream): void {
  stream.write(USAGE);
}

export async function main(argv: readonly string[]): Promise<number> {
  const log = createLogger();

  let cmd: CliCommand;
  try {
    cmd = parseCliArgs(argv);
  } catch (err) {
    if (err instanceof UsageError) {
      process.stderr.write(`remote-mcp: ${err.message}\n\n`);
      printUsage(process.stderr);
      return EXIT.usage;
    }
    log.error({ err: serializeError(err) }, 'failed to parse arguments');
    return EXIT.internal;
  }

  switch (cmd.kind) {
    case 'help':
      printUsage(process.stdout);
      return EXIT.ok;
    case 'version':
      process.stdout.write(`${VERSION}\n`);
      return EXIT.ok;
    case 'serve':
      return serve({ log, env: process.env, configPath: cmd.configPath });
    case 'trust':
      return runTrustCommand(cmd, log);
  }
}

async function runTrustCommand(
  cmd: Extract<CliCommand, { kind: 'trust' }>,
  log: Logger,
): Promise<number> {
  try {
    const paths = resolvePaths({ explicit: cmd.configPath, env: process.env });
    const config = await loadConfig(paths);
    const host = effectiveHost(config, cmd.alias);
    const outcome = await runTrustFlow({
      host,
      paths,
      rotate: cmd.rotate,
      interactive: cmd.interactive,
      ...(cmd.fingerprint !== undefined ? { assumedFingerprint: cmd.fingerprint } : {}),
      log,
      stdin: process.stdin,
      // 交互提示走 stderr，stdout 只保留最终结果
      stdout: process.stderr,
    });
    if (outcome.ok) {
      process.stdout.write(`${outcome.message}\n`);
      return EXIT.ok;
    }
    process.stderr.write(`${outcome.message}\n`);
    return EXIT.trustFailed;
  } catch (err) {
    if (err instanceof ConfigError || err instanceof UsageError) {
      process.stderr.write(`remote-mcp: ${err.message}\n`);
      return EXIT.config;
    }
    log.error({ err: serializeError(err) }, 'trust command failed');
    return EXIT.internal;
  }
}

export interface SignalHandlerOptions {
  /** 只会被调用一次。reason 为触发来源（信号名或 stdin_end / stdin_close）。 */
  onShutdown: (reason: string) => void;
  stdin: Pick<NodeJS.EventEmitter, 'on' | 'removeListener'>;
  signals?: readonly NodeJS.Signals[];
}

const DEFAULT_SIGNALS: readonly NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGHUP'];

/** 安装信号与 stdin 关闭监听。返回卸载函数（幂等）。 */
export function installSignalHandlers(opts: SignalHandlerOptions): () => void {
  const signals = opts.signals ?? DEFAULT_SIGNALS;
  let fired = false;
  const fire = (reason: string): void => {
    if (fired) return;
    fired = true;
    try {
      opts.onShutdown(reason);
    } catch {
      // 关闭回调的异常不向外传播
    }
  };

  const signalListeners = signals.map((sig) => {
    const listener = (): void => fire(sig);
    process.on(sig, listener);
    return { sig, listener };
  });

  const stdinEvents = ['end', 'close'] as const;
  const stdinListeners = stdinEvents.map((ev) => {
    const listener = (): void => fire(`stdin_${ev}`);
    opts.stdin.on(ev, listener);
    return { ev, listener };
  });

  let uninstalled = false;
  return () => {
    if (uninstalled) return;
    uninstalled = true;
    for (const { sig, listener } of signalListeners) process.removeListener(sig, listener);
    for (const { ev, listener } of stdinListeners) opts.stdin.removeListener(ev, listener);
  };
}

let shutdownPromise: Promise<void> | undefined;

/**
 * 关闭：杀掉所有受跟踪的子进程，最多等待 graceMs。幂等（同一进程内只执行一次）。
 * 永不 reject。
 */
export function shutdown(opts: { reason: string; log: Logger; graceMs?: number }): Promise<void> {
  if (shutdownPromise === undefined) {
    shutdownPromise = runShutdown(opts);
  }
  return shutdownPromise;
}

async function runShutdown(opts: { reason: string; log: Logger; graceMs?: number }): Promise<void> {
  const { reason, log, graceMs = 2000 } = opts;
  try {
    log.info({ reason }, 'shutting down');
    const killing = killAllTrackedChildren().catch((err: unknown) => {
      log.warn({ err: serializeError(err) }, 'failed to terminate tracked children');
    });
    const result = await withTimeout(killing, graceMs);
    if (!result.ok) {
      log.warn({ graceMs }, 'child termination exceeded grace period');
    }
  } catch (err) {
    try {
      log.warn({ err: serializeError(err) }, 'shutdown encountered an error');
    } catch {
      // 日志失败不影响关闭
    }
  }
}

export type TimeoutResult<T> = { ok: true; value: T } | { ok: false; timedOut: true };

/**
 * 等待 p 至多 ms 毫秒。超时时调用 onAbort（异常被吞掉）并返回 timedOut，不 reject。
 * p 自身的 reject 原样传播。
 */
export async function withTimeout<T>(
  p: Promise<T>,
  ms: number,
  onAbort?: () => void,
): Promise<TimeoutResult<T>> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<TimeoutResult<T>>((resolve) => {
    timer = setTimeout(() => {
      try {
        onAbort?.();
      } catch {
        // onAbort 的异常不影响超时结果
      }
      resolve({ ok: false, timedOut: true });
    }, ms);
  });
  const settled = p.then((value): TimeoutResult<T> => ({ ok: true, value }));
  try {
    return await Promise.race([settled, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** 可被 AbortSignal 取消的延时。取消时以 AbortError reject。 */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const abortError = (): Error => Object.assign(new Error('sleep aborted'), { name: 'AbortError' });
    if (signal?.aborted === true) {
      reject(abortError());
      return;
    }
    let timer: ReturnType<typeof setTimeout> | undefined;
    const onAbort = (): void => {
      if (timer !== undefined) clearTimeout(timer);
      reject(abortError());
    };
    timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}
