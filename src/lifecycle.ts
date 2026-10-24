import { flushAuditSinks } from './audit/sink.js';
import { serializeError } from './log.js';
import { killAllTrackedChildren } from './ssh/runner.js';
import type { Logger } from './types.js';

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

/** 退出前等待审计队列落盘的上限；超时只 warn，不阻止退出。 */
export const DEFAULT_AUDIT_FLUSH_MS = 1000;

let shutdownPromise: Promise<void> | undefined;

/**
 * 有界地等待所有审计 sink 的队列排空。永不 reject，失败/超时只写 warn。
 * server.ts 的两条关闭路径与 shutdown 在退出前都会调用它。
 */
export async function flushAuditBeforeExit(
  log: Logger,
  timeoutMs: number = DEFAULT_AUDIT_FLUSH_MS,
): Promise<void> {
  try {
    const result = await withTimeout(flushAuditSinks(), timeoutMs);
    if (!result.ok) {
      try {
        log.warn({ timeoutMs }, 'audit flush exceeded shutdown budget');
      } catch {
        // 日志失败不影响退出。
      }
    }
  } catch (err) {
    try {
      log.warn({ err: serializeError(err) }, 'audit flush failed');
    } catch {
      // 日志失败不影响退出。
    }
  }
}

/**
 * 关闭：杀掉所有受跟踪的子进程，最多等待 graceMs；随后有界地 flush 审计。
 * 幂等（同一进程内只执行一次）。永不 reject。
 */
export function shutdown(opts: {
  reason: string;
  log: Logger;
  graceMs?: number;
  auditFlushMs?: number;
}): Promise<void> {
  if (shutdownPromise === undefined) {
    shutdownPromise = runShutdown(opts);
  }
  return shutdownPromise;
}

async function runShutdown(opts: {
  reason: string;
  log: Logger;
  graceMs?: number;
  auditFlushMs?: number;
}): Promise<void> {
  const { reason, log, graceMs = 2000, auditFlushMs = DEFAULT_AUDIT_FLUSH_MS } = opts;
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
  } finally {
    // 无论子进程终止是否报错，都尝试把已排队的审计写完。
    await flushAuditBeforeExit(log, auditFlushMs);
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

// 保持原有导入路径可用；实现集中在 util/time（该项只依赖标准库，无循环依赖）。
export { sleep } from './util/time.js';
