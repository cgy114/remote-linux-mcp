import { beforeAll, describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config/load.js';
import { resolvePaths } from '../../src/config/paths.js';
import { createLogger } from '../../src/log.js';
import { sshExec } from '../../src/tools/ssh-exec.js';
import type { ToolContext } from '../../src/tools/common.js';
import type { RemoteConfig } from '../../src/types.js';

const E2E = process.env.REMOTE_MCP_E2E === '1';
const ALIAS = 'orangepi';
const TIMEOUT_MS = 20_000;

interface ExecStructured {
  exit_code: number | null;
  stdout: string;
  stderr: string;
  timed_out: boolean;
  stdout_bytes: number;
  stderr_bytes: number;
}

function structuredOf(result: { structuredContent?: unknown }): ExecStructured {
  return result.structuredContent as ExecStructured;
}

/**
 * 真实主机集成测试。默认跳过；REMOTE_MCP_E2E=1 时使用真实配置、验证 ssh_exec 的
 * 退出码语义、cwd/env/stdin 透传、UTF-8 与流分离、超时。
 */
describe.skipIf(!E2E)('integration: ssh_exec on real host (orangepi)', () => {
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

  it('echo hello exits 0 and returns stdout', async () => {
    const result = await sshExec({ host: ALIAS, command: 'echo hello' }, ctx);
    const s = structuredOf(result);
    console.log('[ssh_exec:echo] ' + JSON.stringify(s));
    expect(result.isError).not.toBe(true);
    expect(s.exit_code).toBe(0);
    expect(s.stdout).toContain('hello');
  }, TIMEOUT_MS);

  it('maps a remote exit code of 7 to exit_code 7 without isError', async () => {
    // 直接 exit；不要用 `sh -c`（内置 hard 规则会拒绝 shell 解释器）。
    const result = await sshExec({ host: ALIAS, command: 'exit 7' }, ctx);
    const s = structuredOf(result);
    console.log('[ssh_exec:exit7] ' + JSON.stringify(s));
    expect(s.exit_code).toBe(7);
    expect(result.isError).not.toBe(true);
  }, TIMEOUT_MS);

  it('runs in the requested cwd', async () => {
    const result = await sshExec({ host: ALIAS, command: 'pwd', cwd: '/tmp' }, ctx);
    const s = structuredOf(result);
    console.log('[ssh_exec:cwd] ' + JSON.stringify(s));
    expect(result.isError).not.toBe(true);
    expect(s.exit_code).toBe(0);
    expect(s.stdout.trim()).toBe('/tmp');
  }, TIMEOUT_MS);

  it('exports env variables to the remote command', async () => {
    const result = await sshExec(
      { host: ALIAS, command: 'printf %s "$FOO"', env: { FOO: 'bar' } },
      ctx,
    );
    const s = structuredOf(result);
    console.log('[ssh_exec:env] ' + JSON.stringify(s));
    expect(result.isError).not.toBe(true);
    expect(s.exit_code).toBe(0);
    expect(s.stdout).toBe('bar');
  }, TIMEOUT_MS);

  it('forwards stdin to the remote command', async () => {
    const result = await sshExec(
      { host: ALIAS, command: 'cat', stdin: 'ping\n' },
      ctx,
    );
    const s = structuredOf(result);
    console.log('[ssh_exec:stdin] ' + JSON.stringify(s));
    expect(result.isError).not.toBe(true);
    expect(s.exit_code).toBe(0);
    expect(s.stdout).toContain('ping');
  }, TIMEOUT_MS);

  it('preserves UTF-8 output exactly', async () => {
    const result = await sshExec({ host: ALIAS, command: "printf '中文😀'" }, ctx);
    const s = structuredOf(result);
    console.log('[ssh_exec:utf8] ' + JSON.stringify(s));
    expect(result.isError).not.toBe(true);
    expect(s.exit_code).toBe(0);
    expect(s.stdout).toBe('中文😀');
  }, TIMEOUT_MS);

  it('keeps stdout and stderr separate', async () => {
    const result = await sshExec({ host: ALIAS, command: 'echo out; echo err >&2' }, ctx);
    const s = structuredOf(result);
    console.log('[ssh_exec:streams] ' + JSON.stringify(s));
    expect(result.isError).not.toBe(true);
    expect(s.exit_code).toBe(0);
    expect(s.stdout).toContain('out');
    expect(s.stdout).not.toContain('err');
    expect(s.stderr).toContain('err');
    expect(s.stderr).not.toContain('out');
  }, TIMEOUT_MS);

  it('times out a long-running command', async () => {
    const result = await sshExec({ host: ALIAS, command: 'sleep 2', timeout_ms: 500 }, ctx);
    const s = structuredOf(result);
    console.log('[ssh_exec:timeout] ' + JSON.stringify(s));
    expect(s.timed_out).toBe(true);
    expect(result.isError).toBe(true);
  }, TIMEOUT_MS);
});
