import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import { main, parseCliArgs, runCredentialCommand } from '../../src/cli.js';
import { EXIT } from '../../src/constants.js';
import { CredentialError, MemoryCredentialProvider } from '../../src/credentials/index.js';
import { createMcpServer, registerTools } from '../../src/server.js';
import { UsageError } from '../../src/errors/classes.js';
import { VERSION } from '../../src/version.js';
import type { Logger } from '../../src/types.js';

function usageMessage(argv: string[]): string {
  try {
    parseCliArgs(argv);
  } catch (err) {
    expect(err).toBeInstanceOf(UsageError);
    return (err as Error).message;
  }
  throw new Error(`expected UsageError for ${JSON.stringify(argv)}`);
}

describe('parseCliArgs', () => {
  it('defaults to serve with no args', () => {
    expect(parseCliArgs([])).toEqual({ kind: 'serve' });
  });

  it('passes --config through to serve', () => {
    expect(parseCliArgs(['--config', '/tmp/c.yaml'])).toEqual({ kind: 'serve', configPath: '/tmp/c.yaml' });
  });

  it('recognises help and version in short and long form', () => {
    expect(parseCliArgs(['--help'])).toEqual({ kind: 'help' });
    expect(parseCliArgs(['-h'])).toEqual({ kind: 'help' });
    expect(parseCliArgs(['--version'])).toEqual({ kind: 'version' });
    expect(parseCliArgs(['-v'])).toEqual({ kind: 'version' });
  });

  it('parses trust with defaults as interactive', () => {
    expect(parseCliArgs(['trust', 'web1'])).toEqual({
      kind: 'trust',
      alias: 'web1',
      rotate: false,
      interactive: true,
    });
  });

  it('parses trust with rotate and fingerprint as non-interactive', () => {
    const cmd = parseCliArgs(['trust', 'web1', '--rotate', '--fingerprint', 'SHA256:abc', '--config', 'x.yaml']);
    expect(cmd).toEqual({
      kind: 'trust',
      alias: 'web1',
      rotate: true,
      fingerprint: 'SHA256:abc',
      interactive: false,
      configPath: 'x.yaml',
    });
  });

  it('rejects an unknown option', () => {
    expect(usageMessage(['--nope'])).toMatch(/nope/);
  });

  it('rejects an unknown command', () => {
    expect(usageMessage(['frobnicate'])).toMatch(/unknown command: frobnicate/);
  });

  it('rejects trust without an alias', () => {
    expect(usageMessage(['trust'])).toMatch(/requires an alias/);
  });

  it('rejects extra positionals after trust alias', () => {
    expect(usageMessage(['trust', 'a', 'b'])).toMatch(/extra arguments/);
  });

  it('rejects fingerprint without SHA256 prefix', () => {
    expect(usageMessage(['trust', 'a', '--fingerprint', 'MD5:xx'])).toMatch(/SHA256:/);
  });

  it('rejects --rotate and --fingerprint on serve', () => {
    expect(usageMessage(['--rotate'])).toMatch(/only to the trust/);
    expect(usageMessage(['--fingerprint', 'SHA256:x'])).toMatch(/only to the trust/);
  });

  it('parses credential set/status/delete', () => {
    expect(parseCliArgs(['credential', 'set', 'sudo.web1', '--stdin'])).toEqual({
      kind: 'credential',
      action: 'set',
      ref: 'sudo.web1',
      stdin: true,
    });
    expect(parseCliArgs(['credential', 'status', 'sudo.web1'])).toEqual({
      kind: 'credential',
      action: 'status',
      ref: 'sudo.web1',
      stdin: false,
    });
    expect(parseCliArgs(['credential', 'delete', 'sudo.web1'])).toEqual({
      kind: 'credential',
      action: 'delete',
      ref: 'sudo.web1',
      stdin: false,
    });
  });

  it('rejects malformed credential commands', () => {
    expect(usageMessage(['credential'])).toMatch(/subcommand/);
    expect(usageMessage(['credential', 'frobnicate', 'ref'])).toMatch(/subcommand/);
    expect(usageMessage(['credential', 'set'])).toMatch(/requires a name/);
    expect(usageMessage(['credential', 'set', 'a', 'b'])).toMatch(/extra arguments/);
    expect(usageMessage(['credential', 'status', 'ref', '--stdin'])).toMatch(
      /--stdin applies only to credential set/,
    );
    expect(usageMessage(['credential', 'set', 'ref', '--rotate'])).toMatch(/only to the trust/);
    expect(usageMessage(['trust', 'web1', '--stdin'])).toMatch(
      /--stdin applies only to credential set/,
    );
  });

  it('does not accept --password (secret must come from stdin)', () => {
    expect(usageMessage(['credential', 'set', 'ref', '--password', 'hunter2'])).toMatch(
      /password/,
    );
  });
});

describe('main', () => {
  let dir: string;
  let out: string;
  let err: string;
  let stdoutSpy: { mockRestore: () => void };
  let stderrSpy: { mockRestore: () => void };

  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-cli-'));
    out = '';
    err = '';
    stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(((
      chunk: string | Uint8Array,
    ) => {
      out += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
      return true;
    }) as typeof process.stdout.write);
    stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(((
      chunk: string | Uint8Array,
    ) => {
      err += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
      return true;
    }) as typeof process.stderr.write);
  });

  afterEach(async () => {
    stdoutSpy.mockRestore();
    stderrSpy.mockRestore();
    await fs.rm(dir, { recursive: true, force: true });
  });

  async function writeConfig(body: string): Promise<string> {
    const file = path.join(dir, 'config.yaml');
    await fs.writeFile(file, body, 'utf8');
    return file;
  }

  it('--help prints usage to stdout and exits ok', async () => {
    await expect(main(['--help'])).resolves.toBe(EXIT.ok);
    expect(out).toContain('用法');
    expect(out).toContain('remote-mcp trust <alias>');
    expect(out).toContain('--fingerprint');
    expect(err).toBe('');
  });

  it('--version prints the version to stdout and exits ok', async () => {
    await expect(main(['--version'])).resolves.toBe(EXIT.ok);
    expect(out.trim()).toBe(VERSION);
  });

  it('an unknown command exits usage and prints usage to stderr', async () => {
    await expect(main(['nonsense'])).resolves.toBe(EXIT.usage);
    expect(err).toContain('unknown command: nonsense');
    expect(err).toContain('用法');
    expect(out).toBe('');
  });

  it('trust without an alias exits usage', async () => {
    await expect(main(['trust'])).resolves.toBe(EXIT.usage);
    expect(err).toContain('requires an alias');
  });

  it('trust with an unknown alias in a valid config exits config', async () => {
    const cfg = await writeConfig('version: 1\nhosts:\n  web:\n    host: example.invalid\n    user: deploy\n');
    await expect(main(['trust', 'missing', '--config', cfg])).resolves.toBe(EXIT.config);
    expect(err).toContain('unknown host alias: missing');
  });

  it('trust with an unreadable config path exits config', async () => {
    const missing = path.join(dir, 'does-not-exist.yaml');
    await expect(main(['trust', 'web', '--config', missing])).resolves.toBe(EXIT.config);
    expect(err).toContain('config file not found');
  });
});

describe('runCredentialCommand', () => {
  const log: Logger = {
    debug: () => undefined,
    info: () => undefined,
    warn: () => undefined,
    error: () => undefined,
    child: () => log,
  };

  interface Capture {
    stream: NodeJS.WritableStream;
    text: () => string;
  }

  function capture(): Capture {
    let text = '';
    return {
      stream: {
        write(chunk: string | Uint8Array): boolean {
          text += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
          return true;
        },
      } as unknown as NodeJS.WritableStream,
      text: () => text,
    };
  }

  function ttyStream(): NodeJS.ReadableStream {
    const stream = new Readable({ read: () => undefined }) as Readable & { isTTY?: boolean };
    stream.isTTY = true;
    return stream;
  }

  const setCmd = (ref: string, stdin: boolean) =>
    ({ kind: 'credential', action: 'set', ref, stdin }) as const;
  const statusCmd = (ref: string) =>
    ({ kind: 'credential', action: 'status', ref, stdin: false }) as const;
  const deleteCmd = (ref: string) =>
    ({ kind: 'credential', action: 'delete', ref, stdin: false }) as const;

  it('set --stdin stores the line and prints only "stored"', async () => {
    const provider = new MemoryCredentialProvider();
    const out = capture();
    const err = capture();

    const code = await runCredentialCommand(setCmd('sudo.web1', true), log, {
      provider,
      stdin: Readable.from(['hunter2\n']),
      stdout: out.stream,
      stderr: err.stream,
    });

    expect(code).toBe(EXIT.ok);
    expect(out.text()).toBe('stored\n');
    expect(err.text()).toBe('');
    await expect(provider.exists('sudo.web1')).resolves.toBe(true);
    const secret = await provider.get('sudo.web1');
    expect(secret.toString()).toBe('hunter2');
    secret.wipe();
  });

  it('set reads a piped stdin without --stdin', async () => {
    const provider = new MemoryCredentialProvider();
    const out = capture();
    const code = await runCredentialCommand(setCmd('ref', false), log, {
      provider,
      stdin: Readable.from(['piped-secret\r\n']),
      stdout: out.stream,
      stderr: capture().stream,
    });
    expect(code).toBe(EXIT.ok);
    const secret = await provider.get('ref');
    expect(secret.toString()).toBe('piped-secret');
    secret.wipe();
  });

  it('set refuses a TTY without --stdin', async () => {
    const provider = new MemoryCredentialProvider();
    const err = capture();
    const code = await runCredentialCommand(setCmd('ref', false), log, {
      provider,
      stdin: ttyStream(),
      stdout: capture().stream,
      stderr: err.stream,
    });
    expect(code).toBe(EXIT.usage);
    expect(err.text()).toMatch(/--stdin/);
    await expect(provider.exists('ref')).resolves.toBe(false);
  });

  it('set rejects an empty line and never echoes it', async () => {
    const provider = new MemoryCredentialProvider();
    const out = capture();
    const err = capture();
    const code = await runCredentialCommand(setCmd('ref', true), log, {
      provider,
      stdin: Readable.from(['\n']),
      stdout: out.stream,
      stderr: err.stream,
    });
    expect(code).toBe(EXIT.config);
    expect(out.text()).toBe('');
    expect(err.text()).toMatch(/must not be empty/);
  });

  it('set rejects an invalid credential name as a usage error', async () => {
    const provider = new MemoryCredentialProvider();
    const err = capture();
    const code = await runCredentialCommand(setCmd('bad name', true), log, {
      provider,
      stdin: Readable.from(['hunter2\n']),
      stdout: capture().stream,
      stderr: err.stream,
    });
    expect(code).toBe(EXIT.usage);
    expect(err.text()).toMatch(/credential name/);
    expect(err.text()).not.toContain('hunter2');
  });

  it('status/delete also reject an invalid credential name as usage', async () => {
    for (const cmd of [statusCmd('bad/name'), deleteCmd('bad name')]) {
      const err = capture();
      const code = await runCredentialCommand(cmd, log, {
        provider: new MemoryCredentialProvider(),
        stdout: capture().stream,
        stderr: err.stream,
      });
      expect(code).toBe(EXIT.usage);
      expect(err.text()).toMatch(/credential name/);
    }
  });

  it('status reports present/not found without exposing the secret', async () => {
    const provider = new MemoryCredentialProvider({ ref: 'hunter2' });
    const present = capture();
    expect(
      await runCredentialCommand(statusCmd('ref'), log, {
        provider,
        stdout: present.stream,
        stderr: capture().stream,
      }),
    ).toBe(EXIT.ok);
    expect(present.text()).toBe('present\n');

    const missing = capture();
    expect(
      await runCredentialCommand(statusCmd('absent'), log, {
        provider,
        stdout: missing.stream,
        stderr: capture().stream,
      }),
    ).toBe(EXIT.ok);
    expect(missing.text()).toBe('not found\n');
    expect(present.text()).not.toContain('hunter2');
  });

  it('delete removes a credential and reports the outcome', async () => {
    const provider = new MemoryCredentialProvider({ ref: 'hunter2' });
    const out = capture();
    expect(
      await runCredentialCommand(deleteCmd('ref'), log, {
        provider,
        stdout: out.stream,
        stderr: capture().stream,
      }),
    ).toBe(EXIT.ok);
    expect(out.text()).toBe('deleted\n');

    const again = capture();
    await runCredentialCommand(deleteCmd('ref'), log, {
      provider,
      stdout: again.stream,
      stderr: capture().stream,
    });
    expect(again.text()).toBe('not found\n');
  });

  it('maps an unavailable backend to EXIT.internal without leaking details', async () => {
    const provider = {
      id: 'broken',
      async get(): Promise<never> {
        throw new CredentialError('credential_unavailable', 'store offline');
      },
      async set(): Promise<void> {
        throw new CredentialError('credential_unavailable', 'store offline');
      },
      async delete(): Promise<boolean> {
        throw new CredentialError('credential_unavailable', 'store offline');
      },
      async exists(): Promise<boolean> {
        throw new CredentialError('credential_unavailable', 'store offline');
      },
    };
    const err = capture();
    const code = await runCredentialCommand(statusCmd('ref'), log, {
      provider,
      stdout: capture().stream,
      stderr: err.stream,
    });
    expect(code).toBe(EXIT.internal);
    expect(err.text()).toMatch(/unavailable/);
    expect(err.text()).not.toContain('store offline');
  });
});

describe('server wiring', () => {
  const log: Logger = {
    debug: () => undefined,
    info: () => undefined,
    warn: () => undefined,
    error: () => undefined,
    child: () => log,
  };
  const ctx = {
    paths: {} as never,
    log,
    getConfig: async () => {
      throw new Error('not used in smoke test');
    },
  };

  it('createMcpServer returns an McpServer instance', () => {
    expect(createMcpServer(ctx)).toBeInstanceOf(McpServer);
  });

  it('registerTools registers host_list and host_check without throwing', () => {
    const server = createMcpServer(ctx);
    expect(() => registerTools(server, ctx)).not.toThrow();
  });
});
