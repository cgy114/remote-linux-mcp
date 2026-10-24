import { UsageError } from '../errors/classes.js';
import { withHostLease } from '../pipeline/lease.js';
import type { HostLimiter } from '../ssh/host-limiter.js';
import type { Logger } from '../types.js';
import { MAX_QUEUED_COMMANDS } from './constants.js';
import { encodeCommandLine } from './frame.js';
import { createOutputCapture } from './output.js';
import type { TransportEvent, SessionTransport } from './transport.js';
import type {
  CapturedOutput,
  CloseFacts,
  FrameParseErrorCode,
  SendOutcome,
  SessionId,
  SessionState,
  Snapshot,
} from './types.js';

/** 会话所属目标：alias 用于展示/审计，destination 用于主机租约。 */
export interface SessionTarget {
  alias: string;
  destination: string;
  /** 未显式提供 timeout_ms 时的命令超时。 */
  defaultTimeoutMs?: number;
  /** 未显式提供 max_output_bytes 时的输出上限。 */
  defaultMaxOutputBytes?: number;
}

export interface SessionSendInput {
  command: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
}

/** send 的执行事实：SendOutcome 加上两级排队时间。 */
export interface SessionSendResult {
  outcome: SendOutcome;
  /** 等待主机并发许可的毫秒数。 */
  queueMs: number;
  /** 在会话 FIFO 中等待的毫秒数（不含主机租约）。 */
  sessionQueueMs: number;
}

export interface Session {
  readonly id: SessionId;
  readonly alias: string;
  readonly destination: string;
  readonly cwd: string;
  readonly envKeys: readonly string[];
  readonly idleTimeoutMs: number;
  readonly state: SessionState;
  snapshot(): Snapshot;
  send(input: SessionSendInput): Promise<SessionSendResult>;
  /** 幂等；永不 reject。 */
  close(reason?: string): Promise<CloseFacts>;
  /**
   * 注册一个在会话进入 closed 后调用一次的回调（登记簿用它自动释放名额）。
   * 若注册时会话已关闭，回调会在微任务中补发一次；回调异常被吞掉并记录 warn。
   */
  addClosedListener(listener: (sessionId: SessionId) => void): void;
}

export interface CreateSessionOptions {
  id: SessionId;
  target: SessionTarget;
  transport: SessionTransport;
  cwd: string;
  envKeys: readonly string[];
  idleTimeoutMs: number;
  /** 指定时改为周期性检查空闲（毫秒）；否则使用一次性定时器。 */
  idleSweepMs?: number;
  log: Logger;
  /** 测试用：注入计数 limiter；默认进程单例。 */
  limiter?: HostLimiter;
  /** 会话内等待队列上限；默认 MAX_QUEUED_COMMANDS。 */
  maxQueue?: number;
  /** 未指定 timeoutMs 且 target 无默认值时的兜底。 */
  defaultTimeoutMs?: number;
  /** 未指定 maxOutputBytes 且 target 无默认值时的兜底。 */
  defaultMaxOutputBytes?: number;
  /**
   * 会话进入 closed 后调用一次（所有路径：显式 close、idle、timeout、
   * protocol_error、transport_exit）。幂等；异常被吞掉并记录 warn。
   */
  onClosed?: (sessionId: SessionId) => void;
  /**
   * 会话进入 closed 后调用一次（所有路径：显式 close、idle、timeout、
   * protocol_error、transport_exit、shutdown）。在 notifyClosed 之后调用；
   * 返回的 Promise 会被 await，异常被吞掉并记录 warn。
   */
  onAuditClose?: (facts: CloseFacts) => void | Promise<void>;
}

interface QueueEntry {
  input: SessionSendInput;
  enqueuedAt: number;
  resolve: (result: SessionSendResult) => void;
  reject: (error: unknown) => void;
}

interface ActiveCommand {
  seq: number;
  input: SessionSendInput;
  capture: ReturnType<typeof createOutputCapture>;
  written: boolean;
  sawBegin: boolean;
  settled: boolean;
  startedAt: number;
  timer: NodeJS.Timeout | undefined;
  queueMs: number;
  sessionQueueMs: number;
  resolve: (result: SessionSendResult) => void;
  completion: Promise<void>;
  resolveCompletion: () => void;
}

const FALLBACK_TIMEOUT_MS = 15_000;
const FALLBACK_MAX_OUTPUT_BYTES = 1024 * 1024;

function closedError(id: SessionId): UsageError {
  return new UsageError(`session ${id} is closed`, { code: 'session_closed' });
}

/**
 * 创建会话状态机：FIFO 串行执行命令，seq 从 1 递增；只在命令执行期间持有
 * 主机租约。RDY 之后 attach 到传输层。
 */
export function createSession(opts: CreateSessionOptions): Session {
  const {
    id,
    target,
    transport,
    cwd,
    envKeys,
    idleTimeoutMs,
    idleSweepMs,
    log,
    limiter,
    maxQueue = MAX_QUEUED_COMMANDS,
  } = opts;

  const defaultTimeoutMs =
    opts.defaultTimeoutMs ?? target.defaultTimeoutMs ?? FALLBACK_TIMEOUT_MS;
  const defaultMaxOutputBytes =
    opts.defaultMaxOutputBytes ?? target.defaultMaxOutputBytes ?? FALLBACK_MAX_OUTPUT_BYTES;

  const createdAt = Date.now();
  let lastActivity = createdAt;
  let state: SessionState = 'ready';
  let seq = 0;
  let active: ActiveCommand | undefined;
  const queue: QueueEntry[] = [];
  let draining = false;
  let idleTimer: NodeJS.Timeout | undefined;
  let closePromise: Promise<CloseFacts> | undefined;
  let closeFacts: CloseFacts | undefined;
  let commandsRun = 0;
  let outputBytes = 0;
  let truncatedAny = false;
  let closedNotified = false;
  let auditCloseNotified = false;
  const closedListeners: Array<(sessionId: SessionId) => void> = [];
  if (opts.onClosed !== undefined) closedListeners.push(opts.onClosed);

  const invokeClosedListener = (listener: (sessionId: SessionId) => void): void => {
    try {
      listener(id);
    } catch (err) {
      try {
        log.warn(
          { err: err instanceof Error ? err.message : String(err) },
          'session onClosed listener failed',
        );
      } catch {
        // 日志失败不影响关闭
      }
    }
  };

  /** 进入 closed 后恰好通知一次；登记簿删除等副作用都放在这里。 */
  const notifyClosed = (): void => {
    if (closedNotified) return;
    closedNotified = true;
    for (const listener of closedListeners) invokeClosedListener(listener);
  };

  /** 关闭审计回调：notifyClosed 之后恰好一次；异常只记 warn。 */
  const notifyAuditClose = async (facts: CloseFacts): Promise<void> => {
    if (opts.onAuditClose === undefined || auditCloseNotified) return;
    auditCloseNotified = true;
    try {
      await opts.onAuditClose(facts);
    } catch (err) {
      try {
        log.warn(
          { err: err instanceof Error ? err.message : String(err) },
          'session onAuditClose callback failed',
        );
      } catch {
        // 日志失败不影响关闭
      }
    }
  };

  const clearIdle = (): void => {
    if (idleTimer !== undefined) {
      clearTimeout(idleTimer);
      clearInterval(idleTimer);
      idleTimer = undefined;
    }
  };

  const idleExpired = (): boolean => Date.now() - lastActivity >= idleTimeoutMs;

  const armIdle = (): void => {
    clearIdle();
    if (state !== 'ready' || active !== undefined || queue.length > 0) return;
    if (idleSweepMs !== undefined && idleSweepMs > 0) {
      idleTimer = setInterval(() => {
        if (state !== 'ready' || active !== undefined || queue.length > 0) {
          clearIdle();
          return;
        }
        if (idleExpired()) void close('idle_timeout');
      }, Math.max(1, idleSweepMs));
    } else {
      idleTimer = setTimeout(() => {
        if (state === 'ready' && active === undefined && queue.length === 0 && idleExpired()) {
          void close('idle_timeout');
        }
      }, idleTimeoutMs);
    }
    idleTimer.unref?.();
  };

  const durationOf = (cmd: ActiveCommand): number => Math.max(0, Date.now() - cmd.startedAt);

  const outcomeOutput = (cmd: ActiveCommand): CapturedOutput => cmd.capture.finish();

  const settleActive = (cmd: ActiveCommand, outcome: SendOutcome): void => {
    if (cmd.settled) return;
    cmd.settled = true;
    if (cmd.timer !== undefined) {
      clearTimeout(cmd.timer);
      cmd.timer = undefined;
    }
    const output = outcomeOutput(cmd);
    outputBytes += output.bytes;
    if (output.truncated) truncatedAny = true;
    if (active === cmd) active = undefined;
    lastActivity = Date.now();
    cmd.resolve({ outcome, queueMs: cmd.queueMs, sessionQueueMs: cmd.sessionQueueMs });
    cmd.resolveCompletion();
  };

  const protocolFailure = (cmdMessage: string, code: FrameParseErrorCode): void => {
    if (active !== undefined) {
      const cmd = active;
      settleActive(cmd, {
        status: 'error',
        seq: cmd.seq,
        output: outcomeOutput(cmd),
        duration_ms: durationOf(cmd),
        error: code,
        message: cmdMessage,
      });
    }
    void close('protocol_error');
  };

  const handleEvent = (event: TransportEvent): void => {
    if (state === 'closing' || state === 'closed') return;

    if (event.type === 'data') {
      if (active !== undefined && active.sawBegin) active.capture.push(event.buf);
      // B..E 之外的数据（背景输出）丢弃。
      return;
    }

    if (event.type === 'parse_error') {
      protocolFailure(`frame parser failed: ${event.error}`, event.error);
      return;
    }

    if (event.type === 'exit') {
      handleTransportExit();
      return;
    }

    const frame = event.frame;
    if (frame.type === 'RDY') {
      protocolFailure('received an unexpected RDY frame', 'bad_frame');
      return;
    }
    if (frame.type === 'B') {
      if (active === undefined || !active.written || active.sawBegin || active.seq !== frame.seq) {
        protocolFailure(`unexpected B frame for seq ${frame.seq}`, 'bad_frame');
        return;
      }
      active.sawBegin = true;
      return;
    }
    if (
      active === undefined ||
      !active.written ||
      !active.sawBegin ||
      active.seq !== frame.seq
    ) {
      protocolFailure(`unexpected E frame for seq ${frame.seq}`, 'bad_frame');
      return;
    }
    const cmd = active;
    settleActive(cmd, {
      status: 'ok',
      seq: cmd.seq,
      rc: frame.rc,
      output: outcomeOutput(cmd),
      duration_ms: durationOf(cmd),
    });
  };

  const handleTransportExit = (): void => {
    if (state === 'closing' || state === 'closed') return;
    if (active !== undefined && !active.settled) {
      const cmd = active;
      settleActive(cmd, {
        status: 'error',
        seq: cmd.seq,
        output: outcomeOutput(cmd),
        duration_ms: durationOf(cmd),
        error: 'io',
        message: 'session transport exited',
      });
    }
    void close('transport_exit');
  };

  void transport.exited.then(
    () => handleTransportExit(),
    () => handleTransportExit(),
  );

  const executeActive = async (cmd: ActiveCommand): Promise<void> => {
    try {
      await withHostLease(
        target.destination,
        async (lease) => {
          cmd.queueMs = lease.queueMs;
          if (cmd.settled || state === 'closing' || state === 'closed') {
            if (!cmd.settled) {
              settleActive(cmd, {
                status: 'closed',
                seq: cmd.seq,
                output: outcomeOutput(cmd),
                duration_ms: durationOf(cmd),
              });
            }
            return;
          }

          cmd.startedAt = Date.now();
          cmd.written = true;
          cmd.timer = setTimeout(() => {
            if (cmd.settled) return;
            settleActive(cmd, {
              status: 'timeout',
              seq: cmd.seq,
              output: outcomeOutput(cmd),
              duration_ms: durationOf(cmd),
            });
            void close('command_timeout');
          }, cmd.input.timeoutMs ?? defaultTimeoutMs);
          cmd.timer.unref?.();

          try {
            await transport.writeLine(encodeCommandLine(cmd.seq, cmd.input.command));
            commandsRun += 1;
          } catch (err) {
            settleActive(cmd, {
              status: 'error',
              seq: cmd.seq,
              output: outcomeOutput(cmd),
              duration_ms: durationOf(cmd),
              error: 'io',
              message: err instanceof Error ? err.message : String(err),
            });
            void close('transport_error');
            return;
          }

          await cmd.completion;
        },
        limiter,
      );
    } catch (err) {
      settleActive(cmd, {
        status: 'error',
        seq: cmd.seq,
        output: outcomeOutput(cmd),
        duration_ms: durationOf(cmd),
        error: 'io',
        message: err instanceof Error ? err.message : String(err),
      });
      void close('transport_error');
    }
  };

  const settleQueuedClosed = (): void => {
    const entries = queue.splice(0, queue.length);
    for (const entry of entries) entry.reject(closedError(id));
  };

  const drainQueue = async (): Promise<void> => {
    if (draining) return;
    draining = true;
    try {
      while (queue.length > 0) {
        if (state === 'closing' || state === 'closed') {
          settleQueuedClosed();
          break;
        }
        const entry = queue.shift();
        if (entry === undefined) break;

        const currentSeq = (seq += 1);
        const capture = createOutputCapture(
          entry.input.maxOutputBytes ?? defaultMaxOutputBytes,
        );
        let resolveCompletion: () => void = () => undefined;
        const completion = new Promise<void>((resolve) => {
          resolveCompletion = resolve;
        });
        const cmd: ActiveCommand = {
          seq: currentSeq,
          input: entry.input,
          capture,
          written: false,
          sawBegin: false,
          settled: false,
          startedAt: Date.now(),
          timer: undefined,
          queueMs: 0,
          sessionQueueMs: Math.max(0, Date.now() - entry.enqueuedAt),
          resolve: entry.resolve,
          completion,
          resolveCompletion,
        };
        active = cmd;
        state = 'busy';
        clearIdle();

        void executeActive(cmd).catch(() => undefined);
        await completion;

        if (state === 'busy' && queue.length === 0) {
          state = 'ready';
          armIdle();
        }
      }
    } finally {
      draining = false;
    }
  };

  const close = (reason = 'explicit'): Promise<CloseFacts> => {
    closePromise ??= performClose(reason);
    return closePromise;
  };

  async function performClose(reason: string): Promise<CloseFacts> {
    const lifetime = Date.now() - createdAt;
    if (state === 'closed' && closeFacts !== undefined) return closeFacts;
    state = 'closing';
    clearIdle();

    if (active !== undefined && !active.settled) {
      const cmd = active;
      settleActive(cmd, {
        status: 'closed',
        seq: cmd.seq,
        output: outcomeOutput(cmd),
        duration_ms: durationOf(cmd),
      });
    }
    settleQueuedClosed();

    let transportFacts: {
      exit_code: number | null;
      signal: string | null;
      graceful: boolean;
      killed: boolean;
    } = { exit_code: null, signal: null, graceful: false, killed: false };
    try {
      transportFacts = await transport.close();
    } catch (err) {
      try {
        log.warn({ err: err instanceof Error ? err.message : String(err) }, 'session transport close failed');
      } catch {
        // 日志失败不影响关闭
      }
    }

    closeFacts = {
      exit_code: transportFacts.exit_code,
      signal: transportFacts.signal,
      graceful: transportFacts.graceful,
      killed: transportFacts.killed,
      duration_ms: lifetime,
      reason,
    };
    state = 'closed';
    lastActivity = Date.now();
    notifyClosed();
    await notifyAuditClose(closeFacts);
    return closeFacts;
  }

  const send = (input: SessionSendInput): Promise<SessionSendResult> => {
    if (state === 'closing' || state === 'closed') return Promise.reject(closedError(id));
    if (queue.length >= maxQueue) {
      return Promise.reject(
        new UsageError(`session ${id} busy: queue is full (${maxQueue})`, { code: 'session_busy' }),
      );
    }
    lastActivity = Date.now();
    clearIdle();
    return new Promise<SessionSendResult>((resolve, reject) => {
      queue.push({ input, enqueuedAt: Date.now(), resolve, reject });
      void drainQueue();
    });
  };

  const session: Session = {
    id,
    alias: target.alias,
    destination: target.destination,
    cwd,
    envKeys: [...envKeys],
    idleTimeoutMs,
    get state(): SessionState {
      return state;
    },
    snapshot(): Snapshot {
      return {
        id,
        destination: target.destination,
        state,
        created_at: createdAt,
        last_activity_at: lastActivity,
        idle_timeout_ms: idleTimeoutMs,
        queue_depth: queue.length,
        commands_run: commandsRun,
        output_bytes: outputBytes,
        truncated: truncatedAny,
      };
    },
    send,
    close,
    addClosedListener(listener: (sessionId: SessionId) => void): void {
      if (closedNotified || state === 'closed') {
        // 已关闭：补发一次，保持「注册后必被通知」的语义。
        queueMicrotask(() => invokeClosedListener(listener));
        return;
      }
      closedListeners.push(listener);
    },
  };

  transport.attach(handleEvent);
  armIdle();
  return session;
}
