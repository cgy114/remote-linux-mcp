import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { loadConfig, loadConfigLazy } from '../../src/config/load.js';
import { resolvePaths } from '../../src/config/paths.js';
import { buildExecCommand } from '../../src/policy/remote-command.js';
import { effectiveHost } from '../../src/policy/target.js';
import type { ToolContext } from '../../src/tools/common.js';
import {
  EXEC_LIMITS,
  execFailure,
  formatExecResult,
  resolveExecTarget,
  sshExec,
} from '../../src/tools/ssh-exec.js';
import type { Logger, MCPPaths, RunResult } from '../../src/types.js';

const { runSshMock } = vi.hoisted(() => ({ runSshMock: vi.fn() }));

// 只替换 runSsh，保留 runner 的其余导出（known-hosts 等间接依赖 spawnCapture）。
vi.mock('../../src/ssh/runner.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/ssh/runner.js')>();
  return { ...actual, runSsh: runSshMock };
});

const CONFIG_WITH_DEFAULT = `version: 1
defaults:
  default_host: web1
  default_cwd: /home/test
hosts:
  web1:
    host: 10.0.0.5
    user: deploy
  web2:
    host: 10.0.0.6
    user: deploy
`;

const CONFIG_WITHOUT_DEFAULT = `version: 1
hosts:
  web1:
    host: 10.0.0.5
    user: deploy
`;

const KEY_BLOB = Buffer.from('remote-mcp-test-host-key').toString('base64');
const FINGERPRINT = `SHA256:${createHash('sha256')
  .update(Buffer.from(KEY_BLOB, 'base64'))
  .digest('base64')
  .replace(/=+$/, '')}`;

function makeLogger(): Logger {
  const logger: Logger = {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    child: () => logger,
  };
  return logger;
}

function makeRun(overrides: Partial<RunResult> = {}): RunResult {
  return {
    argv: ['ssh', '--', 'deploy@10.0.0.5', '<cmd>'],
    displayCommand: 'ssh -- deploy@10.0.0.5 <cmd>',
    exitCode: 0,
    signal: null,
    stdout: 'hello\n',
    stderr: '',
    stdoutBytes: 6,
    stderrBytes: 0,
    stdoutTruncated: false,
    stderrTruncated: false,
    timedOut: false,
    durationMs: 42,
    ...overrides,
  };
}

function textOf(result: { content: unknown }): string {
  const first = (result.content as Array<{ type: string; text?: string }>)[0];
  return first?.text ?? '';
}

describe('ssh_exec unit', () => {
  let root: string;
  let paths: MCPPaths;
  let ctx: ToolContext;

  async function setup(yaml: string): Promise<void> {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-ssh-exec-'));
    paths = resolvePaths({ explicit: path.join(root, 'config.yaml'), env: {}, homeDir: root });
    await fs.writeFile(paths.configFile, yaml, 'utf8');
    const log = makeLogger();
    ctx = { paths, log, getConfig: loadConfigLazy(paths, log) };
  }

  async function installTrust(): Promise<void> {
    await fs.writeFile(
      paths.trustRegistryFile,
      JSON.stringify({
        version: 1,
        hosts: {
          web1: {
            algorithm: 'ssh-ed25519',
            keyBlob: KEY_BLOB,
            fingerprint: FINGERPRINT,
            firstSeenAt: '2026-10-01T00:00:00Z',
            lastVerifiedAt: '2026-10-01T00:00:00Z',
          },
        },
      }),
      'utf8',
    );
    await fs.writeFile(paths.knownHostsFile, `10.0.0.5 ssh-ed25519 ${KEY_BLOB}\n`, 'utf8');
  }

  beforeEach(async () => {
    runSshMock.mockReset();
    await setup(CONFIG_WITH_DEFAULT);
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  describe('resolveExecTarget', () => {
    it('uses defaults.default_host when host is omitted', async () => {
      const target = await resolveExecTarget({}, ctx);
      expect(target.host.alias).toBe('web1');
      expect(target.destination).toBe('deploy@10.0.0.5:22');
    });

    it('prefers an explicit host over default_host', async () => {
      const target = await resolveExecTarget({ host: 'web2' }, ctx);
      expect(target.host.alias).toBe('web2');
      expect(target.destination).toBe('deploy@10.0.0.6:22');
    });

    it('throws missing_host when neither host nor default_host is set', async () => {
      await setup(CONFIG_WITHOUT_DEFAULT);
      await expect(resolveExecTarget({}, ctx)).rejects.toMatchObject({ code: 'missing_host' });
    });

    it('throws unknown_alias for an alias absent from config', async () => {
      await expect(resolveExecTarget({ host: 'ghost' }, ctx)).rejects.toMatchObject({
        code: 'unknown_alias',
      });
    });
  });

  describe('execFailure', () => {
    it.each([0, 1, 7])('treats exit code %i as a normal remote result', (code) => {
      expect(execFailure(makeRun({ exitCode: code }))).toBeUndefined();
    });

    it('classifies exit 255 with auth stderr as Auth', () => {
      const failure = execFailure(
        makeRun({ exitCode: 255, stderr: 'deploy@10.0.0.5: Permission denied (publickey).' }),
      );
      expect(failure?.kind).toBe('Auth');
    });

    it('maps exit 255 without signatures to Unknown/ssh_transport_failure', () => {
      const failure = execFailure(makeRun({ exitCode: 255, stderr: 'some unparsed failure\n' }));
      expect(failure?.kind).toBe('Unknown');
      expect(failure?.code).toBe('ssh_transport_failure');
      expect(failure?.hint).toBeDefined();
    });

    it('classifies timedOut as Timeout', () => {
      expect(execFailure(makeRun({ exitCode: null, timedOut: true }))?.kind).toBe('Timeout');
    });

    it('classifies spawnError as Internal', () => {
      const failure = execFailure(
        makeRun({ exitCode: null, spawnError: { code: 'ENOENT', message: 'missing ssh' } }),
      );
      expect(failure?.kind).toBe('Internal');
    });
  });

  describe('formatExecResult', () => {
    async function makeFormatInput() {
      const config = await loadConfig(paths);
      const host = effectiveHost(config, 'web1');
      const plan = buildExecCommand({
        command: 'echo hello',
        cwd: '~',
        limits: { maxRemoteUtf16: 28000, maxRemoteUtf8: 1048576 },
      });
      return { alias: 'web1', host, destination: 'deploy@10.0.0.5:22', plan, run: makeRun(), queueMs: 0 };
    }

    it('returns the full structured summary without secrets or argv', async () => {
      const result = formatExecResult(await makeFormatInput());
      expect(result.isError).toBe(false);
      expect(textOf(result).startsWith('web1: exit=0 (42ms)')).toBe(true);

      const structured = result.structuredContent as Record<string, unknown>;
      for (const key of [
        'host',
        'destination',
        'exit_code',
        'stdout',
        'stderr',
        'truncated',
        'timed_out',
        'duration_ms',
        'stdout_bytes',
        'stderr_bytes',
        'stdout_truncated',
        'stderr_truncated',
        'queue_ms',
      ]) {
        expect(structured, `missing ${key}`).toHaveProperty(key);
      }
      expect(structured['exit_code']).toBe(0);
      expect(structured['stdout_bytes']).toBe(6);
      expect(structured).not.toHaveProperty('argv');
      expect(structured).not.toHaveProperty('command');
      expect(structured).not.toHaveProperty('env');
      expect(structured).not.toHaveProperty('stdin');
    });

    it('marks failures as isError with an error object', async () => {
      const input = await makeFormatInput();
      const failure = execFailure(
        makeRun({ exitCode: 255, stderr: 'Permission denied (publickey).' }),
      );
      const result = formatExecResult({ ...input, run: makeRun({ exitCode: 255 }), failure });
      expect(result.isError).toBe(true);
      const structured = result.structuredContent as { error?: { kind?: string; code?: string } };
      expect(structured.error?.kind).toBe('Auth');
      expect(textOf(result)).toContain('error: [Auth]');
    });
  });

  describe('sshExec orchestration', () => {
    it('blocks an untrusted host before spawning ssh', async () => {
      const result = await sshExec({ host: 'web1', command: 'echo hi' }, ctx);
      expect(result.isError).toBe(true);
      expect(textOf(result)).toMatch(/HostKey|trust/i);
      expect(runSshMock).not.toHaveBeenCalled();
    });

    it('runs the command, forwards stdin, uses host defaults and writes an audit record', async () => {
      await installTrust();
      runSshMock.mockResolvedValue(makeRun());

      const first = await sshExec({ host: 'web1', command: 'cat', stdin: 'ping\n' }, ctx);
      expect(first.isError).toBe(false);
      expect(runSshMock).toHaveBeenCalledTimes(1);
      const call = runSshMock.mock.calls[0]?.[0] as Record<string, unknown>;
      expect(call['stdinData']).toBe('ping\n');
      expect(call['timeoutMs']).toBe(15_000);
      expect(call['maxOutputBytes']).toBe(1_048_576);
      expect(call['label']).toBe('ssh_exec:web1');

      // 第二次调用证明 permit 已释放（否则会挂在 limiter 上）。
      runSshMock.mockResolvedValue(makeRun({ exitCode: 3, stdout: '', stderr: 'boom\n' }));
      const second = await sshExec({ host: 'web1', command: 'echo hi' }, ctx);
      expect(second.isError).toBe(false);
      expect(runSshMock).toHaveBeenCalledTimes(2);
      const secondCall = runSshMock.mock.calls[1]?.[0] as Record<string, unknown>;
      expect(secondCall).not.toHaveProperty('stdinData');
      expect((second.structuredContent as { exit_code?: number }).exit_code).toBe(3);

      const auditPath = path.join(paths.configDir, 'audit.jsonl');
      const lines = (await fs.readFile(auditPath, 'utf8')).trim().split(/\r?\n/);
      expect(lines).toHaveLength(2);
      const last = JSON.parse(lines[1] as string) as Record<string, unknown>;
      expect(last['tool']).toBe('ssh_exec');
      expect(last['alias']).toBe('web1');
      expect(last['commandSha256']).toBe(
        createHash('sha256').update('echo hi', 'utf8').digest('hex'),
      );
      expect(last).not.toHaveProperty('argv');
      expect(last).not.toHaveProperty('command');
      expect(JSON.stringify(last)).not.toContain('echo hi');
    });

    it('exposes the expected size limits', () => {
      expect(EXEC_LIMITS.maxCommandBytes).toBe(16_384);
      expect(EXEC_LIMITS.maxStdinBytes).toBe(1_048_576);
      expect(EXEC_LIMITS.maxRemoteUtf16).toBe(28_000);
      expect(EXEC_LIMITS.maxRemoteUtf8).toBe(1_048_576);
    });
  });
});
