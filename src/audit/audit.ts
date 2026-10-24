import { createHash } from 'node:crypto';
import path from 'node:path';
import type { Logger } from '../types.js';
import { appendAuditRecord } from './sink.js';

export { appendAuditRecord } from './sink.js';

export type ExecAuditOutcome =
  | 'ok'
  | 'exit_nonzero'
  | 'transport_failure'
  | 'timeout'
  | 'spawn_error'
  | 'killed'
  | 'denied';

/** 审计记录只存退出事实，不存命令/输出/env 值等任何内容。 */
export interface AuditRunFacts {
  exitCode?: number | null;
  signal?: string | null;
  timedOut?: boolean;
  spawnError?: { code: string; message: string };
  durationMs?: number;
  stdoutBytes?: number;
  stderrBytes?: number;
  /** 完整 argv（含可执行文件）；写入记录时最后一项会被脱敏。 */
  argv?: readonly string[];
}

export interface BuildExecAuditInput {
  alias?: string;
  destination?: string;
  commandSha256: string;
  commandBytes: number;
  cwd?: string;
  envKeys?: readonly string[];
  stdinBytes?: number;
  run?: AuditRunFacts;
  /** 等待主机并发许可的毫秒数。 */
  queueMs?: number;
  /** 未运行就失败时的错误元数据；message 不写入记录。 */
  failure?: { code?: string; kind?: string; message?: string };
  /** 覆盖时间戳（测试用）；默认当前时间。 */
  timestamp?: string;
}

export interface ExecAuditRecord {
  ts: string;
  tool: 'ssh_exec';
  alias?: string;
  destination?: string;
  commandSha256: string;
  commandBytes: number;
  cwd?: string;
  envKeys: string[];
  stdinBytes: number;
  outcome: ExecAuditOutcome;
  exitCode: number | null;
  signal: string | null;
  timedOut: boolean;
  durationMs?: number;
  stdoutBytes?: number;
  stderrBytes?: number;
  /** 脱敏后的 argv；最后一项为命令占位符。 */
  argv?: string[];
  queue_ms?: number;
  failureCode?: string;
  failureKind?: string;
  /** 仅用于 spawn 之前被拒绝的记录。 */
  denied?: boolean;
}

export function auditFilePath(configDir: string): string {
  return path.join(configDir, 'audit.jsonl');
}

export function sha256Hex(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

/** 复制 argv，并把最后一项替换为脱敏后的命令占位；空数组原样返回。 */
export function maskArgv(
  argv: readonly string[],
  commandSha256: string,
  commandBytes: number,
): string[] {
  if (argv.length === 0) return [];
  const masked = [...argv];
  masked[masked.length - 1] = `<redacted command sha256=${commandSha256} bytes=${commandBytes}>`;
  return masked;
}

/**
 * 从运行事实推导审计 outcome。优先级固定：
 * spawn_error > timeout > killed > ok > transport_failure > spawn_error(无退出码)
 * > exit_nonzero。未运行（run 缺失）视为 spawn_error。
 */
export function deriveRunOutcome(input: BuildExecAuditInput): {
  outcome: ExecAuditOutcome;
  exitCode: number | null;
  signal: string | null;
  timedOut: boolean;
} {
  const run = input.run;
  if (run === undefined) {
    return { outcome: 'spawn_error', exitCode: null, signal: null, timedOut: false };
  }
  const exitCode = run.exitCode ?? null;
  const signal = run.signal ?? null;
  const timedOut = run.timedOut === true;

  if (run.spawnError !== undefined) return { outcome: 'spawn_error', exitCode, signal, timedOut };
  if (timedOut) return { outcome: 'timeout', exitCode, signal, timedOut };
  if (signal !== null && signal !== '') return { outcome: 'killed', exitCode, signal, timedOut };
  if (exitCode === 0) return { outcome: 'ok', exitCode, signal, timedOut };
  if (exitCode === 255) return { outcome: 'transport_failure', exitCode, signal, timedOut };
  if (exitCode === null) return { outcome: 'spawn_error', exitCode, signal, timedOut };
  return { outcome: 'exit_nonzero', exitCode, signal, timedOut };
}

/** 生成 ssh_exec 审计记录；不包含命令文本、输出或 env 值。 */
export function buildExecAuditRecord(input: BuildExecAuditInput): ExecAuditRecord {
  const derived = deriveRunOutcome(input);
  const record: ExecAuditRecord = {
    ts: input.timestamp ?? new Date().toISOString(),
    tool: 'ssh_exec',
    commandSha256: input.commandSha256,
    commandBytes: input.commandBytes,
    envKeys: [...(input.envKeys ?? [])],
    stdinBytes: input.stdinBytes ?? 0,
    outcome: derived.outcome,
    exitCode: derived.exitCode,
    signal: derived.signal,
    timedOut: derived.timedOut,
  };

  if (input.alias !== undefined) record.alias = input.alias;
  if (input.destination !== undefined) record.destination = input.destination;
  if (input.cwd !== undefined) record.cwd = input.cwd;
  if (input.run?.durationMs !== undefined) record.durationMs = input.run.durationMs;
  if (input.run?.stdoutBytes !== undefined) record.stdoutBytes = input.run.stdoutBytes;
  if (input.run?.stderrBytes !== undefined) record.stderrBytes = input.run.stderrBytes;
  if (input.run !== undefined) {
    record.argv = maskArgv(input.run.argv ?? [], input.commandSha256, input.commandBytes);
  }
  if (input.queueMs !== undefined) record.queue_ms = input.queueMs;
  if (input.failure?.code !== undefined) record.failureCode = input.failure.code;
  if (input.failure?.kind !== undefined) record.failureKind = input.failure.kind;
  return record;
}

/**
 * 兼容旧调用点的包装：把 file 拆成 configDir + activeFile，交给统一的
 * redact/rotate/append sink。目录自动创建，文件 mode 0o600，永不 reject。
 */
export function appendAudit(record: unknown, opts: { file: string; log: Logger }): Promise<void> {
  return appendAuditRecord(record, {
    configDir: path.dirname(opts.file),
    activeFile: path.basename(opts.file),
    log: opts.log,
  });
}

export type SudoAuditMode = 'off' | 'passwordless' | 'password';

export interface BuildSudoAuditInput extends BuildExecAuditInput {
  sudoMode: SudoAuditMode;
}

export interface SudoAuditRecord extends Omit<ExecAuditRecord, 'tool'> {
  tool: 'ssh_sudo';
  sudo_mode: SudoAuditMode;
}

/**
 * 生成 ssh_sudo 审计记录。与 ssh_exec 的差异只有 tool/sudo_mode；
 * stdinBytes 固定为 0——sudo 密码通过 stdin 传输，但绝不进入审计。
 */
export function buildSudoAuditRecord(input: BuildSudoAuditInput): SudoAuditRecord {
  const { sudoMode, ...rest } = input;
  const base = buildExecAuditRecord({ ...rest, stdinBytes: 0 });
  const record: SudoAuditRecord = {
    ...base,
    tool: 'ssh_sudo',
    sudo_mode: sudoMode,
  };
  if (input.run === undefined && input.failure !== undefined) {
    if (input.failure.kind === 'Policy') {
      record.outcome = 'denied';
      record.denied = true;
    } else if (input.failure.kind === 'Timeout') {
      record.outcome = 'timeout';
    } else {
      record.outcome = 'spawn_error';
    }
  }
  return record;
}
