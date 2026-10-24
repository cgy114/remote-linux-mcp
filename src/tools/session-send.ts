import type { CallToolResult } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { sha256Hex } from '../audit/audit.js';
import { buildSessionSendAudit } from '../session/audit.js';
import { formatSessionSend } from '../session/format.js';
import { validateSessionSendInput as validateSendInput } from '../policy/session.js';
import type { Session } from '../session/session.js';
import {
  errorToToolError,
  toolErrorResult,
  type ToolContext,
} from './common.js';
import {
  appendSessionAudit,
  requireSession,
  sendOutcomeToToolError,
} from './session-common.js';

export const sessionSendInput = z
  .object({
    session_id: z.string().min(1).max(64),
    command: z.string().min(1),
    timeout_ms: z.number().int().min(1).max(600_000).optional(),
    max_output_bytes: z.number().int().min(4096).max(8_388_608).optional(),
  })
  .strict();

export type SessionSendInput = z.infer<typeof sessionSendInput>;

/**
 * session_send：取会话 -> 校验 -> FIFO 执行（持有主机租约）-> 审计 -> 格式化。
 * 超时/协议/IO 失败返回 isError，但退出码非零仍是正常结果（与 ssh_exec 一致）。
 */
export async function sessionSend(
  input: SessionSendInput,
  ctx: ToolContext,
): Promise<CallToolResult> {
  let session: Session | undefined;
  try {
    session = requireSession(input.session_id);
    validateSendInput(input);

    const result = await session.send({
      command: input.command,
      ...(input.timeout_ms !== undefined ? { timeoutMs: input.timeout_ms } : {}),
      ...(input.max_output_bytes !== undefined
        ? { maxOutputBytes: input.max_output_bytes }
        : {}),
    });

    const outcome = result.outcome;
    const failure = sendOutcomeToToolError(session.id, outcome);
    const exitCode = outcome.status === 'ok' ? outcome.rc : null;

    await appendSessionAudit(
      buildSessionSendAudit({
        sessionId: session.id,
        alias: session.alias,
        destination: session.destination,
        cwd: session.cwd,
        seq: outcome.seq,
        commandSha256: sha256Hex(input.command),
        commandBytes: Buffer.byteLength(input.command, 'utf8'),
        exitCode,
        outputBytes: outcome.output.bytes,
        truncated: outcome.output.truncated,
        durationMs: outcome.duration_ms,
        queueMs: result.queueMs,
        sessionQueueMs: result.sessionQueueMs,
        ...(failure !== undefined
          ? { failure: { code: failure.code, kind: failure.kind } }
          : {}),
      }),
      ctx,
    );

    if (failure !== undefined) {
      return toolErrorResult(failure, session.alias, 'session_send');
    }
    if (outcome.status !== 'ok') {
      // 防御：sendOutcomeToToolError 对非 ok 结果必定返回错误。
      return toolErrorResult(
        {
          kind: 'Internal',
          code: 'session_internal_error',
          message: 'session send produced no outcome',
          retryable: false,
        },
        session.alias,
        'session_send',
      );
    }

    return formatSessionSend({
      sessionId: session.id,
      alias: session.alias,
      destination: session.destination,
      exitCode: outcome.rc,
      output: outcome.output,
      durationMs: outcome.duration_ms,
      queueMs: result.queueMs,
      sessionQueueMs: result.sessionQueueMs,
    });
  } catch (e) {
    return toolErrorResult(
      errorToToolError(e, ctx.log),
      session?.alias,
      'session_send',
    );
  }
}
