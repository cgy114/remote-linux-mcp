import { beforeAll, describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config/load.js';
import { resolvePaths } from '../../src/config/paths.js';
import { createLogger } from '../../src/log.js';
import type { ToolContext } from '../../src/tools/common.js';
import { hostCheck } from '../../src/tools/host-check.js';
import { hostList } from '../../src/tools/host-list.js';
import type { RemoteConfig } from '../../src/types.js';

const E2E = process.env.REMOTE_MCP_E2E === '1';
const ALIAS = process.env.REMOTE_MCP_E2E_ALIAS ?? 'orangepi';
const EXPECTED_FINGERPRINT =
  process.env.REMOTE_MCP_E2E_FINGERPRINT ?? 'SHA256:+kpx3mkqNotGheru4rMG3KVrLbhebJhTb74452FHhHw';

interface HostEntry {
  alias: string;
  trusted: boolean;
  pinnedFingerprint?: string;
}

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
  const first = result.content[0];
  return first?.text ?? '';
}

/**
 * 真实环境集成测试。默认跳过，只有显式设置 REMOTE_MCP_E2E=1 时才连接真实主机。
 * 使用真实配置（默认 ~/.remote-mcp/config.yaml，可由 REMOTE_MCP_CONFIG 覆盖）、
 * 专用 known_hosts 与 trust registry；
 * 测试本身只读，不执行 trust、不写远端、不修改任何配置。
 */
describe.skipIf(!E2E)(`integration: real host (${ALIAS})`, () => {
  let ctx: ToolContext;
  let config: RemoteConfig;

  beforeAll(async () => {
    const paths = resolvePaths({ env: process.env });
    config = await loadConfig(paths);
    ctx = {
      paths,
      log: createLogger({ level: 'error' }),
      getConfig: async () => config,
    };
  }, 15_000);

  it('host_list reports the configured alias as trusted with the pinned fingerprint', async () => {
    const result = await hostList({}, ctx);

    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toBeDefined();

    const structured = result.structuredContent as unknown as { hosts: HostEntry[] };
    expect(Array.isArray(structured.hosts)).toBe(true);

    const host = structured.hosts.find((h) => h.alias === ALIAS);
    expect(host).toBeDefined();
    expect(host?.trusted).toBe(true);
    expect(host?.pinnedFingerprint).toBe(EXPECTED_FINGERPRINT);
  });

  it('host_check establishes a real SSH connection and detects Linux', async () => {
    const started = Date.now();
    const result = await hostCheck({ alias: ALIAS }, ctx);
    const elapsedMs = Date.now() - started;

    const text = textOf(result);
    console.log('[host_check] text:\n' + text);
    console.log('[host_check] structuredContent:\n' + JSON.stringify(result.structuredContent, null, 2));
    console.log(`[host_check] elapsedMs=${elapsedMs}`);

    expect(result.isError).not.toBe(true);
    expect(text).toContain('Linux');
    expect(elapsedMs).toBeLessThan(Math.max(15_000, config.defaults.timeouts.checkMs));
  }, 30_000);

  it('host_check rejects an unknown alias with a Policy error', async () => {
    const result = await hostCheck({ alias: 'definitely-missing' }, ctx);

    expect(result.isError).toBe(true);
    const text = textOf(result);
    expect(text).toMatch(/Policy|unknown/);
  }, 15_000);

  // 用例 4：未信任路径需要一份不含该 alias 的 registry 或 known_hosts。
  // 真实环境无法在不写 ~/.remote-mcp 的前提下安全构造（ToolContext 的 paths 只接受同一目录下的
  // 固定文件名），因此按任务约束跳过，不修改真实配置。
  it.skip('host_check blocks an untrusted host before spawning ssh (skipped: would require mutating real registry)', () => {
    // Intentionally empty.
  });
});
