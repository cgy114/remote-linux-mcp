import type { CallToolResult } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { buildSessionCloseAudit } from '../session/audit.js';
import { formatSessionClose } from '../session/format.js';
import type { Session } from '../session/session.js';
import {
  errorToToolError,
  toolErrorResult,
  type ToolContext,
} from './common.js';
import {
  appendSessionAudit,
  requireSession,
  sessionRegistry,
} from './session-common.js';

export const sessionCloseInput = z
  .object({
    session_id: z.string().min(1).max(64),
  })
  .strict();

export type SessionCloseInput = z.infer<typeof sessionCloseInput>;

/**
 * session_close：优雅关闭（Q + EOF，宽限期后强杀），从登记簿移除并审计。
 * 幂等：对已关闭的会话再次调用仍返回同一组事实。
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

    const snapshot = session.snapshot();
    await appendSessionAudit(
      buildSessionCloseAudit({
        sessionId: session.id,
        alias: session.alias,
        destination: session.destination,
        cwd: session.cwd,
        envKeys: session.envKeys,
        commandsRun: snapshot.commands_run,
        outputBytes: snapshot.output_bytes,
        truncated: snapshot.truncated,
        durationMs: facts.duration_ms,
        exitCode: facts.exit_code,
        signal: facts.signal,
        graceful: facts.graceful,
        killed: facts.killed,
      }),
      ctx,
    );

    return formatSessionClose({
      sessionId: session.id,
      alias: session.alias,
      destination: session.destination,
      facts,
    });
  } catch (e) {
    return toolErrorResult(
      errorToToolError(e, ctx.log),
      session?.alias,
      'session_close',
    );
  }
}
