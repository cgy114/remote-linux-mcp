import type { CallToolResult } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { formatSessionClose } from '../session/format.js';
import type { Session } from '../session/session.js';
import {
  toolErrorResult,
  type ToolContext,
} from './common.js';
import {
  requireSession,
  sessionErrorToToolError,
  sessionRegistry,
} from './session-common.js';

export const sessionCloseInput = z
  .object({
    session_id: z.string().min(1).max(64),
  })
  .strict();

export type SessionCloseInput = z.infer<typeof sessionCloseInput>;

/**
 * session_close：优雅关闭（Q + EOF，宽限期后强杀），从登记簿移除。
 * close 审计由 createSession 的 onAuditClose 回调统一写入（所有关闭路径恰好一次），
 * 这里不再重复写。幂等：对已关闭的会话再次调用仍返回同一组事实。
 */
export async function sessionClose(
  input: SessionCloseInput,
  ctx: ToolContext,
): Promise<CallToolResult> {
  let session: Session | undefined;
  try {
    session = requireSession(input.session_id);
    const facts = await session.close('explicit');
    sessionRegistry().delete(session.id);

    return formatSessionClose({
      sessionId: session.id,
      alias: session.alias,
      destination: session.destination,
      facts,
    });
  } catch (e) {
    return toolErrorResult(
      sessionErrorToToolError(e, ctx.log),
      session?.alias,
      'session_close',
    );
  }
}
