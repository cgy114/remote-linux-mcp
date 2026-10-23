import { describe, expect, it } from 'vitest';
import { McpServer } from '@modelcontextprotocol/server';
import { parseCliArgs } from '../../src/lifecycle.js';
import { createMcpServer, registerTools } from '../../src/server.js';
import { UsageError } from '../../src/errors/classes.js';
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
