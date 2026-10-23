import type { CallToolResult } from '@modelcontextprotocol/server';
import type { CheckFacts } from '../types.js';
import { textResult } from './common.js';

export { formatToolError } from '../errors/classify.js';

export interface CheckResultInput {
  alias: string;
  ok: true;
  facts: CheckFacts;
  latencyMs: number;
}

/** host_check 成功结果的文本与 structuredContent。缺省字段显示 unknown。 */
export function formatCheckResult(input: CheckResultInput): CallToolResult {
  const uname = input.facts.uname ?? 'unknown';
  const sshd = input.facts.sshdVersion ?? 'unknown';
  const lines = [
    `${input.alias}: OK (${input.latencyMs}ms)`,
    `uname: ${uname}`,
    `sshd: ${sshd}`,
  ];
  return textResult(lines.join('\n'), {
    alias: input.alias,
    ok: true,
    latencyMs: input.latencyMs,
    uname: input.facts.uname ?? null,
    sshd: input.facts.sshdVersion ?? null,
  });
}
