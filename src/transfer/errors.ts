import { redact } from '../log.js';
import type { RunResult, ToolError } from '../types.js';
import { makeToolError } from '../errors/taxonomy.js';

const STDERR_TAIL_MAX_CHARS = 2000;

/** 只保留 stderr 尾部并脱敏，避免错误详情泄露过多内容。 */
export function stderrTail(stderr: string): string {
  const safe = String(redact(stderr));
  return safe.length > STDERR_TAIL_MAX_CHARS ? safe.slice(-STDERR_TAIL_MAX_CHARS) : safe;
}

/** 用法/策略失败（UsageError 的领域对应物；不抛异常）。 */
export function transferUsage(
  code: string,
  message: string,
  details?: Record<string, unknown>,
): ToolError {
  return makeToolError('Policy', {
    code,
    message,
    ...(details !== undefined ? { details } : {}),
  });
}

/** 明确的策略拒绝。 */
export function policyFailure(
  code: string,
  message: string,
  details?: Record<string, unknown>,
): ToolError {
  return makeToolError('Policy', {
    code,
    message,
    ...(details !== undefined ? { details } : {}),
  });
}

/** 远端命令非零退出 / 被杀。 */
export function remoteFailure(
  code: string,
  message: string,
  details?: Record<string, unknown>,
): ToolError {
  return makeToolError('RemoteExit', {
    code,
    message,
    ...(details !== undefined ? { details } : {}),
  });
}

/** 超时。 */
export function timeoutFailure(message = 'file transfer timed out', details?: Record<string, unknown>): ToolError {
  return makeToolError('Timeout', {
    code: 'transfer_timeout',
    message,
    ...(details !== undefined ? { details } : {}),
  });
}

/** 本地 spawn / I/O / 内部失败。 */
export function internalFailure(
  code = 'transfer_internal_error',
  message = 'file transfer failed internally',
  details?: Record<string, unknown>,
): ToolError {
  return makeToolError('Internal', {
    code,
    message,
    ...(details !== undefined ? { details } : {}),
  });
}

type TransportFacts = Pick<
  RunResult,
  'exitCode' | 'signal' | 'timedOut' | 'spawnError' | 'ioError' | 'stderr'
>;

/**
 * 把一次传输命令的事实归类为 ToolError；undefined 表示成功。
 * 优先级：spawn/io -> Internal，timeout -> Timeout，信号 -> RemoteExit，
 * 255 -> ssh_transport_failure，其余非零 -> remote_exit。
 * successCodes 允许调用方把特定退出码（如 find 的 1）视为非错误。
 */
export function classifyTransportRun(
  run: TransportFacts,
  opts?: { label?: string; successCodes?: readonly number[] },
): ToolError | undefined {
  const label = opts?.label;
  if (run.spawnError !== undefined) {
    return internalFailure('spawn_failed', `${label ?? 'transfer'} could not start`, {
      reason: run.spawnError.code,
    });
  }
  if (run.ioError !== undefined) {
    return internalFailure('local_io_error', `${label ?? 'transfer'} local file I/O failed`, {
      stream: run.ioError.stream,
      reason: run.ioError.code,
    });
  }
  if (run.timedOut) {
    return timeoutFailure(`${label ?? 'transfer'} timed out`);
  }
  const exitCode = run.exitCode;
  if (exitCode !== null && (opts?.successCodes ?? [0]).includes(exitCode)) {
    return undefined;
  }
  if (run.signal !== null && run.signal !== '') {
    return remoteFailure('remote_killed', `${label ?? 'transfer'} was terminated by a signal`, {
      signal: run.signal,
    });
  }
  const details: Record<string, unknown> = {};
  if (exitCode !== null) details['exitCode'] = exitCode;
  if (run.stderr.length > 0) details['stderr'] = stderrTail(run.stderr);
  if (exitCode === 255) {
    return remoteFailure(
      'ssh_transport_failure',
      `${label ?? 'transfer'}: ssh transport failed (exit 255)`,
      details,
    );
  }
  if (exitCode === null) {
    return internalFailure('transfer_no_exit', `${label ?? 'transfer'} exited without a status`, details);
  }
  return remoteFailure('remote_exit', `${label ?? 'transfer'} exited with code ${exitCode}`, details);
}
