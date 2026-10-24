import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config/load.js';
import { resolvePaths } from '../../src/config/paths.js';
import { MemoryCredentialProvider } from '../../src/credentials/index.js';
import { createLogger } from '../../src/log.js';
import { sshSudo } from '../../src/tools/ssh-sudo.js';
import type { ToolContext } from '../../src/tools/common.js';
import type { MCPPaths, RemoteConfig } from '../../src/types.js';

const E2E = process.env.REMOTE_MCP_E2E === '1';
const ALIAS = 'orangepi';
const TIMEOUT_MS = 30_000;

function errorOf(result: { structuredContent?: unknown }): {
  kind?: string;
  code?: string;
} {
  return (result.structuredContent as { error?: { kind?: string; code?: string } }).error ?? {};
}

/**
 * 真实主机上的 ssh_sudo 集成测试。默认跳过；REMOTE_MCP_E2E=1 时启用。
 *
 * 不请求用户密码：password 模式只验证凭据缺失时在 spawn 前失败；
 * passwordless 模式先探测 `sudo -n true`，不可用时跳过并说明原因。
 */
describe.skipIf(!E2E)('integration: ssh_sudo on real host (orangepi)', () => {
  let base: RemoteConfig;
  let paths: MCPPaths;
  let passwordlessCtx: ToolContext;
  let passwordCtx: ToolContext;

  beforeAll(async () => {
    paths = resolvePaths({ env: process.env });
    base = await loadConfig(paths);

    const passwordless: RemoteConfig = {
      ...base,
      defaults: {
        ...base.defaults,
        sudo: { mode: 'passwordless', allow: [], deny: [] },
      },
    };
    passwordlessCtx = {
      paths,
      log: createLogger({ level: 'error' }),
      getConfig: async () => passwordless,
      credentialProvider: new MemoryCredentialProvider(),
    };

    const password: RemoteConfig = {
      ...base,
      defaults: {
        ...base.defaults,
        sudo: { mode: 'password', credential: 'e2e.missing', allow: [], deny: [] },
      },
    };
    passwordCtx = {
      paths,
      log: createLogger({ level: 'error' }),
      getConfig: async () => password,
      credentialProvider: new MemoryCredentialProvider(),
    };
  }, 15_000);

  it('fails with sudo_credential_missing before spawning when no credential is configured', async () => {
    const command = `touch /tmp/remote-mcp-sudo-e2e-missing-${Date.now()}`;
    const result = await sshSudo({ host: ALIAS, command }, passwordCtx);

    console.log('[ssh_sudo:missing] ' + JSON.stringify(result.structuredContent));
    expect(result.isError).toBe(true);
    expect(errorOf(result)).toMatchObject({
      kind: 'Policy',
      code: 'sudo_credential_missing',
    });

    // 零 spawn 的旁证：审计记录没有运行事实（无 argv/exitCode/输出字节），
    // 且 outcome 为 denied。spawn 过的记录一定带 exitCode 与 stdoutBytes。
    const text = await fs.readFile(path.join(paths.configDir, 'audit.jsonl'), 'utf8');
    const sha = createHash('sha256').update(command, 'utf8').digest('hex');
    const record = text
      .split('\n')
      .filter((line) => line !== '')
      .map((line) => JSON.parse(line) as Record<string, unknown>)
      .reverse()
      .find((entry) => entry['tool'] === 'ssh_sudo' && entry['commandSha256'] === sha);

    expect(record).toBeDefined();
    expect(record).toMatchObject({
      tool: 'ssh_sudo',
      sudo_mode: 'password',
      outcome: 'denied',
      denied: true,
      failureCode: 'sudo_credential_missing',
      exitCode: null,
      stdinBytes: 0,
    });
    expect(record).not.toHaveProperty('argv');
    expect(record).not.toHaveProperty('stdoutBytes');
    expect(JSON.stringify(record)).not.toContain('e2e.missing');
  }, TIMEOUT_MS);

  it('runs a passwordless sudo command when sudo -n is available', async () => {
    const probe = await sshSudo({ host: ALIAS, command: 'true' }, passwordlessCtx);
    console.log('[ssh_sudo:passwordless-probe] ' + JSON.stringify(probe.structuredContent));

    if (probe.isError === true) {
      const error = errorOf(probe);
      console.log(
        `[ssh_sudo:passwordless] skipped: remote sudo -n unavailable (kind=${String(
          error.kind,
        )} code=${String(error.code)})`,
      );
      // 远端没有 NOPASSWD 时，正确行为是 SudoPrompt（而不是误报成功）。
      expect(error.kind).toBe('SudoPrompt');
      return;
    }

    const result = await sshSudo({ host: ALIAS, command: 'id -u' }, passwordlessCtx);
    console.log('[ssh_sudo:id-u] ' + JSON.stringify(result.structuredContent));
    expect(result.isError).not.toBe(true);
    const structured = result.structuredContent as { stdout?: string; sudo_mode?: string };
    expect(structured.sudo_mode).toBe('passwordless');
    expect(structured.stdout?.trim()).toBe('0');
  }, TIMEOUT_MS);
});
