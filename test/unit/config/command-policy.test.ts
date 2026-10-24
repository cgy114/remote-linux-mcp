import { describe, expect, it } from 'vitest';
import { ConfigError } from '../../../src/errors/classes.js';
import { auditFor, commandPolicyFor, configSchema, defaultsFor } from '../../../src/config/schema.js';

const HOST = { host: '10.0.0.5', user: 'deploy' };

function base(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { version: 1, hosts: { web1: HOST }, ...extra };
}

function ok(input: unknown): boolean {
  return configSchema.safeParse(input).success;
}

describe('security.command_policy schema', () => {
  it('accepts a full command policy', () => {
    expect(
      ok(
        base({
          security: {
            command_policy: {
              mode: 'enforce',
              use_default_deny: false,
              allow: ['prefix:ls', 're:^df\\s'],
              confirm: ['prefix:systemctl restart'],
              deny: ['prefix:rm -rf'],
            },
          },
        }),
      ),
    ).toBe(true);
  });

  it('rejects unknown fields inside command_policy', () => {
    expect(ok(base({ security: { command_policy: { strict: true } } }))).toBe(false);
  });

  it('rejects an invalid mode', () => {
    expect(ok(base({ security: { command_policy: { mode: 'readonly' } } }))).toBe(false);
  });

  it('rejects invalid regex and empty prefix rules', () => {
    expect(ok(base({ security: { command_policy: { deny: ['re:['] } } }))).toBe(false);
    expect(ok(base({ security: { command_policy: { deny: ['prefix:'] } } }))).toBe(false);
    expect(ok(base({ security: { command_policy: { deny: ['   '] } } }))).toBe(false);
  });

  it('rejects non-string rules', () => {
    expect(ok(base({ security: { command_policy: { deny: [42] } } }))).toBe(false);
  });
});

describe('read_only allow restrictions', () => {
  it('rejects regex allow rules', () => {
    expect(
      ok(base({ security: { command_policy: { mode: 'read_only', allow: ['re:^ls'] } } })),
    ).toBe(false);
  });

  it.each(['bash', 'sh', 'python3', 'perl', 'node', 'awk', 'env', 'xargs', 'find', 'sed', 'tar', 'rsync', 'ssh', 'docker', 'sudo', 'su', 'eval', 'exec', 'source', 'command', 'builtin', 'export', 'set', 'unset', 'alias', 'trap'])(
    'rejects allow %s in read_only mode',
    (program) => {
      expect(
        ok(base({ security: { command_policy: { mode: 'read_only', allow: [`prefix:${program}`] } } })),
      ).toBe(false);
    },
  );

  it('rejects a wrapper prefix that only becomes dangerous after stripping', () => {
    expect(
      ok(base({ security: { command_policy: { mode: 'read_only', allow: ['prefix:command bash'] } } })),
    ).toBe(false);
  });

  it('accepts safe prefix allow rules', () => {
    expect(
      ok(
        base({
          security: {
            command_policy: {
              mode: 'read_only',
              allow: ['prefix:ls', 'prefix:df -h', 'cat'],
              confirm: ['re:^systemctl'],
            },
          },
        }),
      ),
    ).toBe(true);
  });

  it('does not restrict allow rules in enforce mode', () => {
    expect(
      ok(base({ security: { command_policy: { mode: 'enforce', allow: ['re:^ls'] } } })),
    ).toBe(true);
  });
});

describe('security.audit schema', () => {
  it('accepts valid audit settings', () => {
    expect(
      ok(
        base({
          security: { audit: { max_bytes: 1048576, retain_days: 3650, date_rotate: false } },
        }),
      ),
    ).toBe(true);
  });

  it('enforces max_bytes >= 1 MiB', () => {
    expect(ok(base({ security: { audit: { max_bytes: 1024 * 1024 } } }))).toBe(true);
    expect(ok(base({ security: { audit: { max_bytes: 1024 * 1024 - 1 } } }))).toBe(false);
    expect(ok(base({ security: { audit: { max_bytes: 1.5 } } }))).toBe(false);
  });

  it('enforces retain_days 1..3650', () => {
    expect(ok(base({ security: { audit: { retain_days: 1 } } }))).toBe(true);
    expect(ok(base({ security: { audit: { retain_days: 0 } } }))).toBe(false);
    expect(ok(base({ security: { audit: { retain_days: 3651 } } }))).toBe(false);
  });

  it('requires date_rotate to be boolean and rejects unknown fields', () => {
    expect(ok(base({ security: { audit: { date_rotate: 'yes' } } }))).toBe(false);
    expect(ok(base({ security: { audit: { rotate: true } } }))).toBe(false);
  });

  it('expands audit defaults to 16 MiB / 90 days / date rotation', () => {
    expect(auditFor(configSchema.parse(base()))).toEqual({
      maxBytes: 16 * 1024 * 1024,
      retainDays: 90,
      dateRotate: true,
    });
  });

  it('honors explicit audit values', () => {
    const raw = configSchema.parse(
      base({
        security: { audit: { max_bytes: 1024 * 1024, retain_days: 1, date_rotate: false } },
      }),
    );
    expect(auditFor(raw)).toEqual({ maxBytes: 1024 * 1024, retainDays: 1, dateRotate: false });
  });
});

describe('sudo credential validation', () => {
  it.each(['sudo-pw', 'a', 'A.b_c:d-1', 'x'.repeat(128)])('accepts credential %j', (credential) => {
    expect(ok(base({ defaults: { sudo: { mode: 'password', credential } } }))).toBe(true);
  });

  it.each(['-bad', '.bad', 'bad name', 'bad/name', 'x'.repeat(129)])(
    'rejects credential %j',
    (credential) => {
      expect(ok(base({ defaults: { sudo: { mode: 'password', credential } } }))).toBe(false);
    },
  );

  it('requires a credential when sudo.mode is password', () => {
    const raw = configSchema.parse(base({ defaults: { sudo: { mode: 'password' } } }));
    try {
      defaultsFor(raw);
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigError);
      expect((err as ConfigError).code).toBe('schema');
    }
  });

  it('does not require a credential for passwordless or off', () => {
    for (const mode of ['passwordless', 'off']) {
      const raw = configSchema.parse(base({ defaults: { sudo: { mode } } }));
      expect(() => defaultsFor(raw)).not.toThrow();
    }
  });

  it('keeps sudo allow/deny as raw string arrays in Defaults', () => {
    const raw = configSchema.parse(
      base({ defaults: { sudo: { allow: ['systemctl *'], deny: ['re:^rm'] } } }),
    );
    const defaults = defaultsFor(raw);
    expect(defaults.sudo.allow).toEqual(['systemctl *']);
    expect(defaults.sudo.deny).toEqual(['re:^rm']);
  });
});

describe('commandPolicyFor defaults and legacy compatibility', () => {
  it('expands enforce/useDefaultDeny/builtin rules when the section is absent', () => {
    const policy = commandPolicyFor(configSchema.parse(base()));
    expect(policy.mode).toBe('enforce');
    expect(policy.useDefaultDeny).toBe(true);
    expect(policy.allow).toEqual([]);
    expect(policy.confirm).toEqual([]);
    expect(policy.deny.length).toBeGreaterThanOrEqual(30);
    expect(policy.deny.every((rule) => rule.source === 'builtin')).toBe(true);
  });

  it('honors explicit mode/use_default_deny and config rules', () => {
    const policy = commandPolicyFor(
      configSchema.parse(
        base({
          security: {
            command_policy: {
              mode: 'off',
              use_default_deny: false,
              allow: ['prefix:ls'],
              deny: ['prefix:rm -rf'],
            },
          },
        }),
      ),
    );
    expect(policy.mode).toBe('off');
    expect(policy.useDefaultDeny).toBe(false);
    expect(policy.allow).toHaveLength(1);
    expect(policy.deny).toHaveLength(1);
    expect(policy.deny[0]?.source).toBe('config');
  });
});
