import type { CallToolResult } from '@modelcontextprotocol/server';
import type { HostView, MCPPaths } from '../types.js';
import { textResult } from './common.js';

export interface HostListFormatInput {
  hosts: HostView[];
  configPath: string;
  source: MCPPaths['source'];
  degraded: boolean;
}

/**
 * host_list 的文本与 structuredContent。
 * 每行：trusted|untrusted  alias  user@host:port  [SHA256:...|no pin]  - description
 */
export function formatHostList(input: HostListFormatInput): CallToolResult {
  const { hosts, configPath, source, degraded } = input;
  const lines: string[] = [`config: ${configPath} (source=${source})`];
  if (hosts.length === 0) {
    lines.push('(no hosts configured)');
  }
  for (const h of hosts) {
    const trust = h.trusted ? 'trusted' : 'untrusted';
    const pin = h.pinnedFingerprint !== undefined ? `[${h.pinnedFingerprint}]` : '[no pin]';
    const desc = h.description !== undefined && h.description !== '' ? `  - ${h.description}` : '';
    lines.push(`${trust}  ${h.alias}  ${h.user}@${h.host}:${h.port}  ${pin}${desc}`);
  }
  if (degraded) {
    lines.push('warning: trust registry could not be read; all hosts are reported as untrusted');
  }
  return textResult(lines.join('\n'), { configPath, source, degraded, hosts });
}
