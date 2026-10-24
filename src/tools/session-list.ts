import type { CallToolResult } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { formatSessionList, type SessionListEntry } from '../session/format.js';
import {
  errorToToolError,
  toolErrorResult,
  type ToolContext,
} from './common.js';
import { sessionRegistry } from './session-common.js';

export const sessionListInput = z.object({}).strict();

export type SessionListInput = z.infer<typeof sessionListInput>;

/**
 * session_list：列出本进程内的会话状态快照。不建立连接、不占租约、不写审计，
 * 也绝不返回命令、输出内容或 nonce。
 */
export async function sessionList(
  _input: SessionListInput,
  ctx: ToolContext,
): Promise<CallToolResult> {
  try {
    const entries: SessionListEntry[] = sessionRegistry()
      .list()
      .map((session) => ({
        sessionId: session.id,
        alias: session.alias,
        destination: session.destination,
        snapshot: session.snapshot(),
      }));
    return formatSessionList(entries);
  } catch (e) {
    return toolErrorResult(errorToToolError(e, ctx.log), undefined, 'session_list');
  }
}
