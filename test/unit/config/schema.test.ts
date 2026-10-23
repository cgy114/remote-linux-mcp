import { describe, expect, it } from 'vitest';
import { configSchema, defaultsFor } from '../../../src/config/schema.js';

const validHost = { host: '10.0.0.5', user: 'deploy' };
const base = (extra: Record<string, unknown> = {}) => ({
  version: 1,
  hosts: { web1: validHost },
  ...extra,
});

function ok(input: unknown): boolean {
  return configSchema.safeParse(input).success;
}

describe('configSchema', () => {
  it('accepts a minimal valid config', () => {
    expect(ok(base())).toBe(true);
  });

  describe('top level', () => {
    it('rejects a missing version', () => {
      const { version: _v, ...rest } = base();
      expect(ok(rest)).toBe(false);
    });

    it('rejects version other than literal 1', () => {
      expect(ok(base({ version: 2 }))).toBe(false);
      expect(ok(base({ version: '1' }))).toBe(false);
    });

    it('rejects a missing hosts', () => {
      expect(ok({ version: 1 })).toBe(false);
    });

    it('rejects empty hosts', () => {
      expect(ok({ version: 1, hosts: {} })).toBe(false);
    });

    it('rejects unknown top-level fields', () => {
      expect(ok(base({ surprise: true }))).toBe(false);
    });
  });

  describe('defaults', () => {
    it('accepts port as integer in 1..65535', () => {
      expect(ok(base({ defaults: { port: 1 } }))).toBe(true);
      expect(ok(base({ defaults: { port: 65535 } }))).toBe(true);
    });

    it('rejects port as string "22"', () => {
      expect(ok(base({ defaults: { port: '22' } }))).toBe(false);
    });

    it('rejects port 0, 70000, and decimals', () => {
      expect(ok(base({ defaults: { port: 0 } }))).toBe(false);
      expect(ok(base({ defaults: { port: 70000 } }))).toBe(false);
      expect(ok(base({ defaults: { port: 22.5 } }))).toBe(false);
    });

    it('rejects non-positive or non-integer timeouts', () => {
      expect(ok(base({ defaults: { timeouts: { connect_ms: 0 } } }))).toBe(false);
      expect(ok(base({ defaults: { timeouts: { command_ms: 1.5 } } }))).toBe(false);
      expect(ok(base({ defaults: { timeouts: { check_ms: 100 } } }))).toBe(true);
    });

    it('rejects max_output_bytes out of 4096..8388608', () => {
      expect(ok(base({ defaults: { max_output_bytes: 4095 } }))).toBe(false);
      expect(ok(base({ defaults: { max_output_bytes: 8388609 } }))).toBe(false);
      expect(ok(base({ defaults: { max_output_bytes: 4096 } }))).toBe(true);
    });

    it('accepts only off|passwordless|password for sudo.mode', () => {
      expect(ok(base({ defaults: { sudo: { mode: 'password' } } }))).toBe(true);
      expect(ok(base({ defaults: { sudo: { mode: 'root' } } }))).toBe(false);
    });

    it('rejects unknown fields inside defaults and sudo', () => {
      expect(ok(base({ defaults: { nope: 1 } }))).toBe(false);
      expect(ok(base({ defaults: { sudo: { nope: 1 } } }))).toBe(false);
    });
  });

  describe('security', () => {
    it('only accepts host_key_policy pinned', () => {
      expect(ok(base({ security: { host_key_policy: 'pinned' } }))).toBe(true);
      expect(ok(base({ security: { host_key_policy: 'tofu' } }))).toBe(false);
    });

    it('rejects unknown fields inside security', () => {
      expect(ok(base({ security: { strict: true } }))).toBe(false);
    });
  });

  describe('hosts', () => {
    it('requires host and user', () => {
      expect(ok(base({ hosts: { a: { user: 'u' } } }))).toBe(false);
      expect(ok(base({ hosts: { a: { host: 'h' } } }))).toBe(false);
    });

    it('rejects an empty or whitespace-containing host', () => {
      expect(ok(base({ hosts: { a: { host: '', user: 'u' } } }))).toBe(false);
      expect(ok(base({ hosts: { a: { host: 'a b', user: 'u' } } }))).toBe(false);
      expect(ok(base({ hosts: { a: { host: 'a\tb', user: 'u' } } }))).toBe(false);
    });

    it('rejects control characters in host', () => {
      expect(ok(base({ hosts: { a: { host: 'ab', user: 'u' } } }))).toBe(false);
    });

    it('rejects a host starting with "-" (ssh option injection)', () => {
      expect(ok(base({ hosts: { a: { host: '-oProxyCommand=x', user: 'u' } } }))).toBe(false);
    });

    it('validates user against ^[A-Za-z0-9._-]{1,64}$', () => {
      expect(ok(base({ hosts: { a: { host: 'h', user: 'bad user' } } }))).toBe(false);
      expect(ok(base({ hosts: { a: { host: 'h', user: 'x'.repeat(65) } } }))).toBe(false);
      expect(ok(base({ hosts: { a: { host: 'h', user: 'ok.user_1-x' } } }))).toBe(true);
    });

    it('validates optional port range', () => {
      expect(ok(base({ hosts: { a: { ...validHost, port: 2222 } } }))).toBe(true);
      expect(ok(base({ hosts: { a: { ...validHost, port: '2222' } } }))).toBe(false);
      expect(ok(base({ hosts: { a: { ...validHost, port: 0 } } }))).toBe(false);
    });

    it('rejects unknown fields inside a host', () => {
      expect(ok(base({ hosts: { a: { ...validHost, passwd: 'x' } } }))).toBe(false);
    });

    it('accepts all optional host fields', () => {
      expect(
        ok(
          base({
            hosts: {
              a: {
                ...validHost,
                port: 22,
                identity_file: '~/.ssh/id',
                proxy_jump: 'bastion',
                default_cwd: '/srv',
                description: 'web',
              },
            },
          }),
        ),
      ).toBe(true);
    });
  });

  describe('alias keys', () => {
    it.each(['-leading', 'UpperCase', 'has space', '_under', '.dot', ''])('rejects alias %j', (k) => {
      expect(ok(base({ hosts: { [k]: validHost } }))).toBe(false);
    });

    it.each(['default', 'serve', 'trust'])('rejects reserved alias %s', (k) => {
      expect(ok(base({ hosts: { [k]: validHost } }))).toBe(false);
    });

    it('rejects an alias longer than 64 chars', () => {
      expect(ok(base({ hosts: { ['a'.repeat(65)]: validHost } }))).toBe(false);
      expect(ok(base({ hosts: { ['a'.repeat(64)]: validHost } }))).toBe(true);
    });

    it('accepts a normal alias', () => {
      expect(ok(base({ hosts: { 'web-1.prod_a': validHost } }))).toBe(true);
    });
  });
});

describe('defaultsFor', () => {
  it('expands every default when defaults is absent', () => {
    const raw = configSchema.parse(base());
    expect(defaultsFor(raw)).toStrictEqual({
      port: 22,
      defaultCwd: '~',
      timeouts: { connectMs: 5000, commandMs: 15000, checkMs: 8000 },
      maxOutputBytes: 1048576,
      sudo: { mode: 'off', allow: [], deny: [] },
    });
  });

  it('keeps explicit values and includes sudo credential/allow/deny when set', () => {
    const raw = configSchema.parse(
      base({
        defaults: {
          port: 2200,
          default_cwd: '/srv',
          timeouts: { connect_ms: 1000 },
          max_output_bytes: 8192,
          sudo: { mode: 'password', credential: 'sudo-pw', allow: ['systemctl *'], deny: ['rm *'] },
        },
      }),
    );
    expect(defaultsFor(raw)).toStrictEqual({
      port: 2200,
      defaultCwd: '/srv',
      timeouts: { connectMs: 1000, commandMs: 15000, checkMs: 8000 },
      maxOutputBytes: 8192,
      sudo: { mode: 'password', credential: 'sudo-pw', allow: ['systemctl *'], deny: ['rm *'] },
    });
  });
});
