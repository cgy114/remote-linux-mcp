import { appendAudit, auditFilePath } from '../audit/audit.js';
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
import type { ToolError } from '../types.js';
import type { ToolAnnotations, ToolContext } from './common.js';

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

/** 追加一条会话审计记录；appendAudit 永不 reject。 */
export async function appendSessionAudit(
  record: unknown,
  ctx: ToolContext,
): Promise<void> {
  await appendAudit(record, {
    file: auditFilePath(ctx.paths.configDir),
    log: ctx.log,
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
    return makeToolError('Internal', {
      code: 'session_start_failed',
      message: `ssh 会话在 RDY 之前退出（exit=${String(facts.exit_code ?? 'null')}）`,
      details,
    });
  }
  return makeToolError('Internal', {
    code: 'session_start_failed',
    message: err.message,
    details,
  });
}

/** send 的执行结果 -> ToolError；undefined 表示命令正常结束（含非零退出码）。 */
export function sendOutcomeToToolError(
  sessionId: string,
  outcome: SendOutcome,
): ToolError | undefined {
  switch (outcome.status) {
    case 'ok':
      return undefined;
    case 'timeout':
      return makeToolError('Timeout', {
        code: 'session_timeout',
        message: `session ${sessionId} command timed out; the session was closed`,
        details: { session_id: sessionId, seq: outcome.seq },
      });
    case 'closed':
      return makeToolError('Policy', {
        code: 'session_closed',
        message: `session ${sessionId} was closed before the command finished`,
        details: { session_id: sessionId, seq: outcome.seq },
      });
    case 'error':
      return makeToolError('Internal', {
        code: outcome.error === 'io' ? 'session_io_error' : 'session_protocol_error',
        message: outcome.message,
        details: { session_id: sessionId, seq: outcome.seq, frame_error: outcome.error },
      });
  }
}
