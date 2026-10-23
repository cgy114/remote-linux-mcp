export type TransferDirection = 'upload' | 'download' | 'remote_copy';

export type TransferAuditOutcome =
  | 'ok'
  | 'verified'
  | 'denied'
  | 'timeout'
  | 'transport_failure'
  | 'remote_exit'
  | 'spawn_failed'
  | 'verify_failed';

/** 审计只接收事实摘要；调用方不得传入文件内容、stdout/stderr 或凭据。 */
export interface TransferRunFacts {
  exitCode?: number | null;
  signal?: string | null;
  timedOut?: boolean;
  spawnError?: boolean;
  ioError?: boolean;
  durationMs?: number;
  stdoutBytes?: number;
  stderrBytes?: number;
}

export interface TransferAuditInput {
  tool?: string;
  alias?: string;
  destination?: string;
  direction: TransferDirection;
  sourcePath?: string;
  targetPath?: string;
  files?: number;
  bytes?: number;
  run?: TransferRunFacts;
  /** 失败元数据；只记录 code/kind，不记录 message。 */
  failure?: { code?: string; kind?: string };
  verified?: boolean;
  timestamp?: string;
}

export interface TransferAuditRecord {
  ts: string;
  tool: string;
  alias?: string;
  destination?: string;
  direction: TransferDirection;
  sourcePath?: string;
  targetPath?: string;
  files: number;
  bytes: number;
  outcome: TransferAuditOutcome;
  exitCode: number | null;
  signal: string | null;
  timedOut: boolean;
  durationMs?: number;
  stdoutBytes?: number;
  stderrBytes?: number;
  verified?: boolean;
  failureCode?: string;
  failureKind?: string;
}

/**
 * 推导传输审计 outcome。优先级：
 * denied > timeout > spawn_failed > verify_failed > transport_failure > remote_exit > verified > ok。
 */
export function deriveTransferOutcome(input: TransferAuditInput): TransferAuditOutcome {
  const failure = input.failure;
  const run = input.run;
  if (failure?.kind === 'Policy') return 'denied';
  if (run?.timedOut === true || failure?.kind === 'Timeout') return 'timeout';
  if (run?.spawnError === true || run?.ioError === true || failure?.kind === 'Internal') {
    return 'spawn_failed';
  }
  if (failure?.code?.startsWith('verify_') === true || failure?.kind === 'verify') {
    return 'verify_failed';
  }
  const exitCode = run?.exitCode ?? null;
  if (exitCode === 255) return 'transport_failure';
  if (run?.signal !== undefined && run.signal !== null && run.signal !== '') {
    return 'transport_failure';
  }
  if (failure !== undefined && failure.code === 'ssh_transport_failure') return 'transport_failure';
  if (exitCode !== null && exitCode !== 0) return 'remote_exit';
  if (failure !== undefined) return 'remote_exit';
  if (input.verified === true) return 'verified';
  return 'ok';
}

/** 生成传输审计记录；不包含文件内容、输出、env 值或错误 message。 */
export function buildTransferAuditRecord(input: TransferAuditInput): TransferAuditRecord {
  const run = input.run;
  const record: TransferAuditRecord = {
    ts: input.timestamp ?? new Date().toISOString(),
    tool: input.tool ?? 'file_transfer',
    direction: input.direction,
    files: input.files ?? 0,
    bytes: input.bytes ?? 0,
    outcome: deriveTransferOutcome(input),
    exitCode: run?.exitCode ?? null,
    signal: run?.signal ?? null,
    timedOut: run?.timedOut === true,
  };
  if (input.alias !== undefined) record.alias = input.alias;
  if (input.destination !== undefined) record.destination = input.destination;
  if (input.sourcePath !== undefined) record.sourcePath = input.sourcePath;
  if (input.targetPath !== undefined) record.targetPath = input.targetPath;
  if (run?.durationMs !== undefined) record.durationMs = run.durationMs;
  if (run?.stdoutBytes !== undefined) record.stdoutBytes = run.stdoutBytes;
  if (run?.stderrBytes !== undefined) record.stderrBytes = run.stderrBytes;
  if (input.verified !== undefined) record.verified = input.verified;
  if (input.failure?.code !== undefined) record.failureCode = input.failure.code;
  if (input.failure?.kind !== undefined) record.failureKind = input.failure.kind;
  return record;
}
