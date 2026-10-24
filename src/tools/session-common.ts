import { appendAuditRecord } from '../audit/audit.js';
import { UsageError } from '../errors/classes.js';
import { makeToolError } from '../errors/taxonomy.js';
import {
  getSessionRegistry,
  resetSessionRegistry,
  type SessionRegistry,
} from '../session/registry.js';
import type { Session } from '../session/session.js';
import { SessionStartError } from '../session/transport.js';
import type { SendOutcome } from '../session/types.js';
import type { AuditConfig, Logger, ToolError } from '../types.js';
import { errorToToolError, type ToolAnnotations, type ToolContext } from './common.js';

/** 会话专用提示：通用 taxonomy 的 ssh 提示会误导用户。 */
const HINT_SESSION_TIMEOUT = '会话已因命令超时自动关闭；请重新 session_start 并调大 timeout_ms';
const HINT_SESSION_CLOSED = '会话已关闭，请重新创建会话';
const HINT_SESSION_BUSY = '会话或队列已满，等待在途命令完成后重试';
const HINT_SESSION_START = '远端会话在握手前退出；检查远端 cwd 是否存在、bash 与系统资源';

function withHint(err: ToolError, hint: string, retryable?: boolean): ToolError {
  return {
    ...err,
    hint,
    ...(retryable !== undefined ? { retryable } : {}),
  };
}

/** 会话错误码的补充提示/可重试性；其余错误原样返回。 */
export function applySessionErrorHints(err: ToolError): ToolError {
  switch (err.code) {
    case 'session_timeout':
      return withHint(err, HINT_SESSION_TIMEOUT, false);
    case 'session_closed':
      return withHint(err, HINT_SESSION_CLOSED);
    case 'session_busy':
    case 'too_many_sessions':
      return withHint(err, HINT_SESSION_BUSY, true);
    default:
      return err;
  }
}

/** 任意异常 -> 会话工具错误（通用分类之上覆盖 hint/retryable）。 */
export function sessionErrorToToolError(e: unknown, log?: Logger): ToolError {
  return applySessionErrorHints(errorToToolError(e, log));
}

/** 修改型会话工具的统一注解（start 本身不改远端状态）。 */
export const SESSION_START_ANNOTATIONS: ToolAnnotations = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: true,
};

export const SESSION_SEND_ANNOTATIONS: ToolAnnotations = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: true,
};

export const SESSION_CLOSE_ANNOTATIONS: ToolAnnotations = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: true,
  openWorldHint: true,
};

export const SESSION_LIST_ANNOTATIONS: ToolAnnotations = { readOnlyHint: true };

/** 当前登记簿（工具每次调用时动态读取，便于测试 reset）。 */
export function sessionRegistry(): SessionRegistry {
  return getSessionRegistry();
}

/** 测试辅助：替换默认登记簿（不传则下次调用时惰性创建新实例）。 */
export function useSessionRegistry(registry?: SessionRegistry): void {
  resetSessionRegistry(registry);
}

/** 取会话；不存在时抛 UsageError(unknown_session)。 */
export function requireSession(id: string): Session {
  const session = sessionRegistry().get(id);
  if (session === undefined) {
    throw new UsageError(`unknown session ${id}`, { code: 'unknown_session' });
  }
  return session;
}

/** 追加一条会话审计记录；appendAuditRecord 永不 reject。 */
export async function appendSessionAudit(
  record: unknown,
  ctx: ToolContext,
  audit?: AuditConfig,
): Promise<void> {
  await appendAuditRecord(record, {
    configDir: ctx.paths.configDir,
    log: ctx.log,
    ...(audit !== undefined ? { audit } : {}),
  });
}

/** 握手失败 -> ToolError（保留 stderr/pre-RDY 诊断，但不含命令或 env 值）。 */
export function sessionStartErrorToToolError(err: SessionStartError): ToolError {
  const facts = err.facts;
  const details: Record<string, unknown> = {};
  if (facts.stderr !== undefined && facts.stderr.length > 0) details['stderr'] = facts.stderr;
  if (facts.pre_rdy !== undefined && facts.pre_rdy.length > 0) details['pre_rdy'] = facts.pre_rdy;
  if (facts.exit_code !== undefined && facts.exit_code !== null) {
    details['exitCode'] = facts.exit_code;
  }

  if (facts.code === 'session_handshake_timeout') {
    details['timedOut'] = true;
    return makeToolError('Timeout', {
      code: 'session_handshake_timeout',
      message: '远端会话在握手超时前没有返回 RDY',
      details,
    });
  }
  if (facts.code === 'session_protocol_error') {
    return makeToolError('Internal', {
      code: 'session_protocol_error',
      message: `会话握手协议错误${facts.parse_error !== undefined ? `: ${facts.parse_error}` : ''}`,
      details,
    });
  }
  if (facts.code === 'session_exited_early') {
    return withHint(
      makeToolError('Internal', {
        code: 'session_start_failed',
        message: `ssh 会话在 RDY 之前退出（exit=${String(facts.exit_code ?? 'null')}）`,
        details,
      }),
      HINT_SESSION_START,
    );
  }
  const base = makeToolError('Internal', {
    code: 'session_start_failed',
    message: err.message,
    details,
  });
  // 本地 ssh 启动失败时保留 Internal 的本地排查提示；握手后的失败用远端提示。
  return facts.code === 'session_spawn_failed' ? base : withHint(base, HINT_SESSION_START);
}

/** send 的执行结果 -> ToolError；undefined 表示命令正常结束（含非零退出码）。 */
export function sendOutcomeToToolError(
  sessionId: string,
  outcome: SendOutcome,
): ToolError | undefined {
  if (outcome.status === 'ok') return undefined;

  // 失败结果只暴露输出元数据，绝不返回输出正文。
  const details: Record<string, unknown> = {
    session_id: sessionId,
    seq: outcome.seq,
    output_bytes: outcome.output.bytes,
    truncated: outcome.output.truncated,
    encoding: outcome.output.encoding,
    duration_ms: outcome.duration_ms,
    timed_out: outcome.status === 'timeout',
  };

  switch (outcome.status) {
    case 'timeout':
      return withHint(
        makeToolError('Timeout', {
          code: 'session_timeout',
          message: `session ${sessionId} command timed out; the session was closed`,
          details,
        }),
        HINT_SESSION_TIMEOUT,
        false,
      );
    case 'closed':
      return withHint(
        makeToolError('Policy', {
          code: 'session_closed',
          message: `session ${sessionId} was closed before the command finished`,
          details,
        }),
        HINT_SESSION_CLOSED,
      );
    case 'error':
      return makeToolError('Internal', {
        code: outcome.error === 'io' ? 'session_io_error' : 'session_protocol_error',
        message: outcome.message,
        details: { ...details, frame_error: outcome.error },
      });
  }
}
