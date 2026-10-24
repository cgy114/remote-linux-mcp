import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { loadConfigLazy } from '../../src/config/load.js';
import { resolvePaths } from '../../src/config/paths.js';
import {
  CredentialError,
  MemoryCredentialProvider,
  SecretMaterial,
  type CredentialProvider,
} from '../../src/credentials/index.js';
import type { ToolContext } from '../../src/tools/common.js';
import { classifySudoFailure, sshSudo } from '../../src/tools/ssh-sudo.js';
import type { Logger, MCPPaths, RunResult } from '../../src/types.js';

const { runSshMock } = vi.hoisted(() => ({ runSshMock: vi.fn() }));

vi.mock('../../src/ssh/runner.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/ssh/runner.js')>();
  return { ...actual, runSsh: runSshMock };
});

const KEY_BLOB = Buffer.from('remote-mcp-test-host-key').toString('base64');
const FINGERPRINT = `SHA256:${createHash('sha256')
  .update(Buffer.from(KEY_BLOB, 'base64'))
  .digest('base64')
  .replace(/=+$/, '')}`;

const PASSWORD = 'SuperSecret1';

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
    stdout: 'uid=0(root)\n',
    stderr: '',
    stdoutBytes: 12,
    stderrBytes: 0,
    stdoutTruncated: false,
    stderrTruncated: false,
    timedOut: false,
    durationMs: 20,
    ...overrides,
  };
}

function textOf(result: { content: unknown }): string {
  const first = (result.content as Array<{ type: string; text?: string }>)[0];
  return first?.text ?? '';
}

function errorOf(result: { structuredContent?: unknown }): {
  kind?: string;
  code?: string;
  message?: string;
} {
  return (result.structuredContent as { error?: { kind?: string; code?: string; message?: string } })
    .error ?? {};
}

function configYaml(options: {
  sudoMode: 'off' | 'passwordless' | 'password';
  credential?: string;
  commandPolicy?: string;
}): string {
  const credential =
    options.credential !== undefined ? `\n    credential: ${options.credential}` : '';
  const security =
    options.commandPolicy !== undefined ? `security:\n${options.commandPolicy}\n` : '';
  return `version: 1
${security}defaults:
  default_host: web1
  default_cwd: /home/test
  sudo:
    mode: ${options.sudoMode}${credential}
hosts:
  web1:
    host: 10.0.0.5
    user: deploy
`;
}

describe('ssh_sudo unit', () => {
  let root: string;
  let paths: MCPPaths;
  let ctx: ToolContext;
  let credentialProvider: MemoryCredentialProvider;

  async function setup(yaml: string): Promise<void> {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-ssh-sudo-'));
    paths = resolvePaths({ explicit: path.join(root, 'config.yaml'), env: {}, homeDir: root });
    await fs.writeFile(paths.configFile, yaml, 'utf8');
    const log = makeLogger();
    credentialProvider = new MemoryCredentialProvider();
    ctx = {
      paths,
      log,
      getConfig: loadConfigLazy(paths, log),
      credentialProvider,
    };
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

  async function auditRecords(): Promise<Record<string, unknown>[]> {
    const file = path.join(paths.configDir, 'audit.jsonl');
    const text = await fs.readFile(file, 'utf8');
    return text
      .trim()
      .split(/\r?\n/)
      .filter((line) => line !== '')
      .map((line) => JSON.parse(line) as Record<string, unknown>);
  }

  beforeEach(async () => {
    runSshMock.mockReset();
    await setup(configYaml({ sudoMode: 'passwordless' }));
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  it('rejects sudo.mode=off before spawning and writes a denied audit', async () => {
    await setup(configYaml({ sudoMode: 'off' }));
    await installTrust();

    const result = await sshSudo({ host: 'web1', command: 'id' }, ctx);
    expect(result.isError).toBe(true);
    expect(errorOf(result)).toMatchObject({ kind: 'Policy', code: 'sudo_disabled' });
    expect(runSshMock).not.toHaveBeenCalled();

    const records = await auditRecords();
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      tool: 'ssh_sudo',
      sudo_mode: 'off',
      outcome: 'denied',
      denied: true,
      failureKind: 'Policy',
      failureCode: 'sudo_disabled',
      stdinBytes: 0,
    });
  });

  it('rejects read_only mode before spawning', async () => {
    await setup(
      configYaml({
        sudoMode: 'passwordless',
        commandPolicy: '  command_policy:\n    mode: read_only\n    allow:\n      - prefix:ls',
      }),
    );
    await installTrust();

    const result = await sshSudo({ host: 'web1', command: 'ls' }, ctx);
    expect(result.isError).toBe(true);
    expect(errorOf(result)).toMatchObject({ kind: 'Policy', code: 'policy_read_only' });
    expect(runSshMock).not.toHaveBeenCalled();
  });

  it('rejects a command denied by command_policy before spawning', async () => {
    await setup(
      configYaml({
        sudoMode: 'passwordless',
        commandPolicy: '  command_policy:\n    deny:\n      - prefix:reboot',
      }),
    );
    await installTrust();

    const result = await sshSudo({ host: 'web1', command: 'reboot' }, ctx);
    expect(result.isError).toBe(true);
    expect(errorOf(result)).toMatchObject({ kind: 'Policy', code: 'policy_denied' });
    expect(runSshMock).not.toHaveBeenCalled();
  });

  it('runs passwordless sudo with -n and no stdin', async () => {
    await installTrust();
    runSshMock.mockResolvedValue(makeRun());

    const result = await sshSudo({ host: 'web1', command: 'id' }, ctx);
    expect(result.isError).not.toBe(true);

    const call = runSshMock.mock.calls[0]?.[0] as Record<string, unknown>;
    const argv = call['argv'] as string[];
    expect(argv[argv.length - 1]).toContain('sudo -n --');
    expect(call).not.toHaveProperty('stdinData');
    expect(call['label']).toBe('ssh_sudo:web1');
    expect(call['timeoutMs']).toBe(15_000);
    expect(call['maxOutputBytes']).toBe(1_048_576);

    const structured = result.structuredContent as Record<string, unknown>;
    expect(structured['tool']).toBe('ssh_sudo');
    expect(structured['sudo_mode']).toBe('passwordless');

    const records = await auditRecords();
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      tool: 'ssh_sudo',
      sudo_mode: 'passwordless',
      stdinBytes: 0,
      outcome: 'ok',
      alias: 'web1',
      commandSha256: createHash('sha256').update('id').digest('hex'),
      commandBytes: 2,
    });
    expect(JSON.stringify(records[0])).not.toContain('id');
  });

  it('sends a password only through stdin and wipes it', async () => {
    await setup(
      configYaml({ sudoMode: 'password', credential: 'sudo.web1' }),
    );
    await installTrust();
    await credentialProvider.set('sudo.web1', PASSWORD);

    let material: SecretMaterial | undefined;
    const originalGet = credentialProvider.get.bind(credentialProvider);
    credentialProvider.get = async (name: string, options?: { timeoutMs?: number }) => {
      material = await originalGet(name, options);
      return material;
    };

    let seenStdin = '';
    let seenArgv: string[] = [];
    let seenEnv: unknown = {};
    runSshMock.mockImplementation(async (input: Record<string, unknown>) => {
      const stdin = input['stdinData'];
      seenStdin = Buffer.isBuffer(stdin) ? stdin.toString('utf8') : String(stdin);
      seenArgv = [...((input['argv'] as string[] | undefined) ?? [])];
      seenEnv = input['env'];
      return makeRun();
    });

    const result = await sshSudo({ host: 'web1', command: 'id' }, ctx);
    expect(result.isError).not.toBe(true);
    expect(seenStdin).toBe(`${PASSWORD}\n`);
    expect(seenArgv.join(' ')).toContain("sudo -S -k -p '' --");
    expect(seenArgv.join(' ')).not.toContain(PASSWORD);
    expect(JSON.stringify(seenEnv)).not.toContain(PASSWORD);

    const text = textOf(result);
    const structured = JSON.stringify(result.structuredContent);
    expect(text).not.toContain(PASSWORD);
    expect(structured).not.toContain(PASSWORD);
    expect(structured).toContain('"sudo_mode":"password"');

    const records = await auditRecords();
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      tool: 'ssh_sudo',
      sudo_mode: 'password',
      stdinBytes: 0,
    });
    const rawAudit = await fs.readFile(path.join(paths.configDir, 'audit.jsonl'), 'utf8');
    expect(rawAudit).not.toContain(PASSWORD);
    expect(rawAudit).not.toContain('SuperSecret');

    const log = ctx.log as unknown as Record<string, ReturnType<typeof vi.fn>>;
    const logged = ['debug', 'info', 'warn', 'error']
      .map((level) => JSON.stringify(log[level]?.mock.calls ?? []))
      .join('\n');
    expect(logged).not.toContain(PASSWORD);

    expect(material).toBeDefined();
    expect(material?.disposed).toBe(true);
    expect(() => material?.copy()).toThrow();
  });

  it('classifies a wrong sudo password as SudoPrompt', async () => {
    await setup(configYaml({ sudoMode: 'password', credential: 'sudo.web1' }));
    await installTrust();
    await credentialProvider.set('sudo.web1', 'wrong-password');
    runSshMock.mockResolvedValue(
      makeRun({ exitCode: 1, stdout: '', stderr: 'Sorry, try again.\n' }),
    );

    const result = await sshSudo({ host: 'web1', command: 'id' }, ctx);
    expect(result.isError).toBe(true);
    expect(errorOf(result)).toMatchObject({ kind: 'SudoPrompt', code: 'sudo_prompt' });

    const records = await auditRecords();
    expect(records[0]).toMatchObject({ failureKind: 'SudoPrompt', outcome: 'exit_nonzero' });
    expect(JSON.stringify(records[0])).not.toContain('wrong-password');
  });

  it('classifies a TTY requirement as SudoPrompt', async () => {
    await installTrust();
    runSshMock.mockResolvedValue(
      makeRun({
        exitCode: 1,
        stdout: '',
        stderr: 'sudo: a terminal is required to read the password; either use the -S option\n',
      }),
    );

    const result = await sshSudo({ host: 'web1', command: 'id' }, ctx);
    expect(result.isError).toBe(true);
    expect(errorOf(result)).toMatchObject({ kind: 'SudoPrompt', code: 'sudo_prompt' });
  });

  it('maps a missing credential to Policy without spawning', async () => {
    await setup(configYaml({ sudoMode: 'password', credential: 'sudo.web1' }));
    await installTrust();

    const result = await sshSudo({ host: 'web1', command: 'id' }, ctx);
    expect(result.isError).toBe(true);
    expect(errorOf(result)).toMatchObject({
      kind: 'Policy',
      code: 'sudo_credential_missing',
    });
    expect(runSshMock).not.toHaveBeenCalled();

    const records = await auditRecords();
    expect(records[0]).toMatchObject({
      tool: 'ssh_sudo',
      sudo_mode: 'password',
      outcome: 'denied',
      denied: true,
      failureCode: 'sudo_credential_missing',
    });
  });

  it('maps an invalid credential to Policy without spawning', async () => {
    await setup(configYaml({ sudoMode: 'password', credential: 'sudo.web1' }));
    await installTrust();
    const provider: CredentialProvider = {
      id: 'invalid',
      async get() {
        throw new CredentialError('credential_invalid', 'invalid');
      },
    };
    ctx = { ...ctx, credentialProvider: provider };

    const result = await sshSudo({ host: 'web1', command: 'id' }, ctx);
    expect(result.isError).toBe(true);
    expect(errorOf(result)).toMatchObject({
      kind: 'Policy',
      code: 'sudo_credential_invalid',
    });
    expect(runSshMock).not.toHaveBeenCalled();
  });

  it('maps an unavailable credential backend to Internal without spawning', async () => {
    await setup(configYaml({ sudoMode: 'password', credential: 'sudo.web1' }));
    await installTrust();
    const provider: CredentialProvider = {
      id: 'unavailable',
      async get() {
        throw new CredentialError('credential_unavailable', 'backend down');
      },
    };
    ctx = { ...ctx, credentialProvider: provider };

    const result = await sshSudo({ host: 'web1', command: 'id' }, ctx);
    expect(result.isError).toBe(true);
    expect(errorOf(result)).toMatchObject({
      kind: 'Internal',
      code: 'sudo_credential_unavailable',
    });
    expect(runSshMock).not.toHaveBeenCalled();
  });

  it('classifies ssh exit 255 with auth stderr as Auth', async () => {
    await installTrust();
    runSshMock.mockResolvedValue(
      makeRun({
        exitCode: 255,
        stdout: '',
        stderr: 'deploy@10.0.0.5: Permission denied (publickey).',
      }),
    );

    const result = await sshSudo({ host: 'web1', command: 'id' }, ctx);
    expect(result.isError).toBe(true);
    expect(errorOf(result)).toMatchObject({ kind: 'Auth' });
  });

  it('rejects an oversized command before spawning', async () => {
    await installTrust();
    const command = 'a'.repeat(16 * 1024 + 1);

    const result = await sshSudo({ host: 'web1', command }, ctx);
    expect(result.isError).toBe(true);
    expect(errorOf(result)).toMatchObject({ kind: 'Policy', code: 'command_too_large' });
    expect(runSshMock).not.toHaveBeenCalled();
  });

  describe('classifySudoFailure', () => {
    it('prefers sudo signatures over generic exit classification', () => {
      const failure = classifySudoFailure({
        run: makeRun({ exitCode: 1, stderr: 'sudo: no password was provided' }),
      });
      expect(failure?.kind).toBe('SudoPrompt');
    });

    it('treats ordinary non-zero exits as remote results', () => {
      expect(
        classifySudoFailure({ run: makeRun({ exitCode: 3, stderr: 'bash: nope' }) }),
      ).toBeUndefined();
    });

    it('returns credential errors unchanged', () => {
      const err = {
        kind: 'Policy' as const,
        code: 'sudo_credential_missing',
        message: 'missing',
        retryable: false,
      };
      expect(classifySudoFailure({ credentialError: err })).toBe(err);
    });
  });
});
