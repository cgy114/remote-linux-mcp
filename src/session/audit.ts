/**
 * 会话审计记录。只保存身份/摘要/退出事实：
 * 绝不写入命令原文、输出内容、env 值或 nonce。
 */

export type SessionAuditOutcome =
  | 'ok'
  | 'exit_nonzero'
  | 'timeout'
  | 'closed'
  | 'error'
  | 'failed'
  | 'denied';

/** 失败元数据只记录 code/kind，不记录 message。 */
export interface SessionAuditFailure {
  code?: string;
  kind?: string;
}

export interface SessionStartAuditInput {
  sessionId?: string;
  alias?: string;
  destination?: string;
  cwd?: string;
  envKeys?: readonly string[];
  idleTimeoutMs?: number;
  failure?: SessionAuditFailure;
  timestamp?: string;
}

export interface SessionStartAuditRecord {
  ts: string;
  tool: 'session_start';
  session_id?: string;
  alias?: string;
  destination?: string;
  cwd?: string;
  envKeys: string[];
  idle_timeout_ms?: number;
  outcome: SessionAuditOutcome;
  failureCode?: string;
  failureKind?: string;
}

export interface SessionSendAuditInput {
  sessionId: string;
  alias?: string;
  destination?: string;
  cwd?: string;
  seq?: number;
  commandSha256: string;
  commandBytes: number;
  exitCode?: number | null;
  outputBytes?: number;
  truncated?: boolean;
  durationMs?: number;
  /** 等待主机并发许可的毫秒数。 */
  queueMs?: number;
  /** 会话 FIFO 排队毫秒数。 */
  sessionQueueMs?: number;
  /** 覆盖自动推导的 outcome（例如命令未执行就被策略拒绝）。 */
  outcome?: SessionAuditOutcome;
  failure?: SessionAuditFailure;
  timestamp?: string;
}

export interface SessionSendAuditRecord {
  ts: string;
  tool: 'session_send';
  session_id: string;
  alias?: string;
  destination?: string;
  cwd?: string;
  seq?: number;
  commandSha256: string;
  commandBytes: number;
  exitCode: number | null;
  outputBytes: number;
  truncated: boolean;
  durationMs?: number;
  queue_ms: number;
  session_queue_ms: number;
  outcome: SessionAuditOutcome;
  failureCode?: string;
  failureKind?: string;
}

export interface SessionCloseAuditInput {
  sessionId: string;
  alias?: string;
  destination?: string;
  cwd?: string;
  envKeys?: readonly string[];
  commandsRun?: number;
  outputBytes?: number;
  truncated?: boolean;
  durationMs?: number;
  exitCode?: number | null;
  signal?: string | null;
  graceful?: boolean;
  killed?: boolean;
  failure?: SessionAuditFailure;
  timestamp?: string;
}

export interface SessionCloseAuditRecord {
  ts: string;
  tool: 'session_close';
  session_id: string;
  alias?: string;
  destination?: string;
  cwd?: string;
  envKeys: string[];
  commandsRun: number;
  outputBytes: number;
  truncated: boolean;
  durationMs?: number;
  exitCode: number | null;
  signal: string | null;
  graceful: boolean;
  killed: boolean;
  outcome: SessionAuditOutcome;
  failureCode?: string;
  failureKind?: string;
}

/** start 的 outcome 只区分成功与失败（失败即握手/启动被拒）。 */
export function deriveSessionStartOutcome(input: SessionStartAuditInput): SessionAuditOutcome {
  return input.failure !== undefined ? 'failed' : 'ok';
}

/** send 的 outcome 优先级：denied > timeout > error > exit_nonzero > ok。 */
export function deriveSessionSendOutcome(input: SessionSendAuditInput): SessionAuditOutcome {
  if (input.outcome !== undefined) return input.outcome;
  const failure = input.failure;
  if (failure?.kind === 'Policy') return 'denied';
  if (failure?.kind === 'Timeout') return 'timeout';
  if (failure !== undefined) return 'error';
  const exitCode = input.exitCode ?? null;
  if (exitCode !== null && exitCode !== 0) return 'exit_nonzero';
  return 'ok';
}

export function buildSessionStartAudit(input: SessionStartAuditInput): SessionStartAuditRecord {
  const record: SessionStartAuditRecord = {
    ts: input.timestamp ?? new Date().toISOString(),
    tool: 'session_start',
    envKeys: [...(input.envKeys ?? [])],
    outcome: deriveSessionStartOutcome(input),
  };
  if (input.sessionId !== undefined) record.session_id = input.sessionId;
  if (input.alias !== undefined) record.alias = input.alias;
  if (input.destination !== undefined) record.destination = input.destination;
  if (input.cwd !== undefined) record.cwd = input.cwd;
  if (input.idleTimeoutMs !== undefined) record.idle_timeout_ms = input.idleTimeoutMs;
  if (input.failure?.code !== undefined) record.failureCode = input.failure.code;
  if (input.failure?.kind !== undefined) record.failureKind = input.failure.kind;
  return record;
}

export function buildSessionSendAudit(input: SessionSendAuditInput): SessionSendAuditRecord {
  const outcome = deriveSessionSendOutcome(input);
  const record: SessionSendAuditRecord = {
    ts: input.timestamp ?? new Date().toISOString(),
    tool: 'session_send',
    session_id: input.sessionId,
    commandSha256: input.commandSha256,
    commandBytes: input.commandBytes,
    exitCode: input.exitCode ?? null,
    outputBytes: input.outputBytes ?? 0,
    truncated: input.truncated === true,
    queue_ms: input.queueMs ?? 0,
    session_queue_ms: input.sessionQueueMs ?? 0,
    outcome,
  };
  if (input.alias !== undefined) record.alias = input.alias;
  if (input.destination !== undefined) record.destination = input.destination;
  if (input.cwd !== undefined) record.cwd = input.cwd;
  if (input.seq !== undefined) record.seq = input.seq;
  if (input.durationMs !== undefined) record.durationMs = input.durationMs;
  if (input.failure?.code !== undefined) record.failureCode = input.failure.code;
  if (input.failure?.kind !== undefined) record.failureKind = input.failure.kind;
  return record;
}

export function deriveSessionCloseOutcome(input: SessionCloseAuditInput): SessionAuditOutcome {
  return input.failure !== undefined ? 'failed' : 'ok';
}

export function buildSessionCloseAudit(input: SessionCloseAuditInput): SessionCloseAuditRecord {
  const record: SessionCloseAuditRecord = {
    ts: input.timestamp ?? new Date().toISOString(),
    tool: 'session_close',
    session_id: input.sessionId,
    envKeys: [...(input.envKeys ?? [])],
    commandsRun: input.commandsRun ?? 0,
    outputBytes: input.outputBytes ?? 0,
    truncated: input.truncated === true,
    exitCode: input.exitCode ?? null,
    signal: input.signal ?? null,
    graceful: input.graceful === true,
    killed: input.killed === true,
    outcome: deriveSessionCloseOutcome(input),
  };
  if (input.alias !== undefined) record.alias = input.alias;
  if (input.destination !== undefined) record.destination = input.destination;
  if (input.cwd !== undefined) record.cwd = input.cwd;
  if (input.durationMs !== undefined) record.durationMs = input.durationMs;
  if (input.failure?.code !== undefined) record.failureCode = input.failure.code;
  if (input.failure?.kind !== undefined) record.failureKind = input.failure.kind;
  return record;
}
