import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import { main, parseCliArgs } from '../../src/cli.js';
import { EXIT } from '../../src/constants.js';
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
