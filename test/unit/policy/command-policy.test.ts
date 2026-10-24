import { describe, expect, it } from 'vitest';
import { UsageError } from '../../../src/errors/classes.js';
import {
  assertCommandPolicy,
  evaluateCommandPolicy,
  evaluateSudoPolicy,
} from '../../../src/policy/command-policy.js';
import { compileCommandPolicy } from '../../../src/policy/command-rules.js';
import type { CommandPolicy, Defaults } from '../../../src/types.js';

const READ_ONLY = compileCommandPolicy({
  mode: 'read_only',
  allow: ['prefix:ls', 'prefix:df', 'prefix:cat', 'prefix:grep'],
});

function ro(command: string, extra: { envKeys?: string[]; surface?: 'ssh_exec' | 'session_send' | 'ssh_sudo' } = {}) {
  return evaluateCommandPolicy({
    command,
    policy: READ_ONLY,
    surface: extra.surface ?? 'ssh_exec',
    ...(extra.envKeys !== undefined ? { envKeys: extra.envKeys } : {}),
  });
}

describe('read_only mode', () => {
  it('allows commands matching an allow prefix', () => {
    expect(ro('ls -la').action).toBe('allow');
    expect(ro('df -h').action).toBe('allow');
    expect(ro('cat /etc/hostname').action).toBe('allow');
    expect(ro('ls; ls').action).toBe('allow');
  });

  it('denies everything when allow is empty', () => {
    const policy = compileCommandPolicy({ mode: 'read_only' });
    const decision = evaluateCommandPolicy({ command: 'ls', policy, surface: 'ssh_exec' });
    expect(decision.action).toBe('deny');
    expect(decision.code).toBe('policy_read_only_allowlist_empty');
  });

  it('denies a second segment that is not allowed', () => {
    const decision = ro('ls; rm -rf /tmp/build');
    expect(decision.action).toBe('deny');
    expect(decision.code).toBe('policy_not_allowed');
  });

  it('denies redirections, command substitution, background execution and pipes to denied commands', () => {
    expect(ro('ls > /tmp/out').action).toBe('deny');
    expect(ro('ls < /etc/passwd').action).toBe('deny');
    expect(ro('ls 2>&1').action).toBe('deny');
    expect(ro('ls $(id)').action).toBe('deny');
    expect(ro('ls `id`').action).toBe('deny');
    expect(ro('ls &').action).toBe('deny');
    expect(ro('ls | rm -rf /tmp/x').action).toBe('deny');
  });

  it('allows quoted operator characters that are only arguments', () => {
    expect(ro('ls ">"').action).toBe('allow');
  });

  it('denies sensitive env keys from the tool and inline assignments', () => {
    expect(ro('ls', { envKeys: ['PATH'] }).code).toBe('policy_read_only_env');
    expect(ro('LD_PRELOAD=/evil.so ls').code).toBe('policy_read_only_env');
    expect(ro('ls', { envKeys: ['FOO'] }).action).toBe('allow');
  });

  it('rejects surface types that can execute arbitrary commands', () => {
    expect(ro('ls', { surface: 'session_send' }).code).toBe('policy_read_only');
    expect(ro('ls', { surface: 'ssh_sudo' }).code).toBe('policy_read_only');
  });

  it('denies shell wrappers even when their inner command is allow-listed', () => {
    for (const command of ['timeout 10 df -h', 'nohup df -h', 'nice -n 5 df -h']) {
      const decision = ro(command);
      expect(decision.action).toBe('deny');
      expect(decision.code).toBe('policy_read_only_unsafe');
    }
  });

  it('denies interpreters even if a programmatic policy allows them', () => {
    const policy = compileCommandPolicy({
      mode: 'read_only',
      use_default_deny: false,
      allow: ['prefix:bash'],
    });
    const decision = evaluateCommandPolicy({ command: 'bash -c ls', policy, surface: 'ssh_exec' });
    expect(decision.action).toBe('deny');
    expect(decision.code).toBe('policy_read_only_unsafe');
  });

  it('allows a pipe when every segment is allowed', () => {
    expect(ro('ls | cat').action).toBe('allow');
  });
});

describe('sensitive env keys', () => {
  it.each(['GIT_SSH', 'GIT_SSH_VARIANT', 'GIT_SSH_COMMAND'])(
    'treats %s as sensitive',
    (key) => {
      expect(ro('ls', { envKeys: [key] }).code).toBe('policy_read_only_env');
    },
  );
});

describe('decision priority', () => {
  it('lets deny win over allow and confirm', () => {
    const policy = compileCommandPolicy({
      allow: ['prefix:systemctl'],
      confirm: ['prefix:systemctl status'],
      deny: ['prefix:systemctl status'],
    });
    const decision = evaluateCommandPolicy({
      command: 'systemctl status nginx',
      policy,
      surface: 'ssh_exec',
    });
    expect(decision.action).toBe('deny');
  });

  it('lets deny win regardless of rule order', () => {
    const policy = compileCommandPolicy({
      deny: ['re:systemctl\\s+status'],
      allow: ['prefix:systemctl'],
    });
    expect(
      evaluateCommandPolicy({ command: 'systemctl status nginx', policy, surface: 'ssh_exec' }).action,
    ).toBe('deny');
  });

  it('lets confirm win over allow', () => {
    const policy = compileCommandPolicy({
      allow: ['prefix:systemctl'],
      confirm: ['prefix:systemctl restart'],
    });
    expect(
      evaluateCommandPolicy({ command: 'systemctl restart nginx', policy, surface: 'ssh_exec' })
        .action,
    ).toBe('confirm');
    expect(
      evaluateCommandPolicy({ command: 'systemctl status nginx', policy, surface: 'ssh_exec' }).action,
    ).toBe('allow');
  });

  it('confirms when any segment matches', () => {
    const policy = compileCommandPolicy({
      allow: ['prefix:ls', 'prefix:systemctl'],
      confirm: ['prefix:systemctl restart'],
    });
    expect(
      evaluateCommandPolicy({ command: 'ls && systemctl restart nginx', policy, surface: 'ssh_exec' })
        .action,
    ).toBe('confirm');
  });

  it('enforces allow rules on every segment in enforce mode', () => {
    const policy = compileCommandPolicy({ allow: ['prefix:ls'] });
    expect(evaluateCommandPolicy({ command: 'ls -la', policy, surface: 'ssh_exec' }).action).toBe(
      'allow',
    );
    expect(evaluateCommandPolicy({ command: 'ls; cat x', policy, surface: 'ssh_exec' }).action).toBe(
      'deny',
    );
  });

  it('allows by default in enforce mode when no allow rules exist', () => {
    const policy = compileCommandPolicy({ use_default_deny: false });
    expect(evaluateCommandPolicy({ command: 'whoami', policy, surface: 'ssh_exec' }).action).toBe(
      'allow',
    );
  });

  it('mode=off allows everything', () => {
    const policy = compileCommandPolicy({ mode: 'off', deny: ['prefix:rm -rf'] });
    expect(evaluateCommandPolicy({ command: 'rm -rf /', policy, surface: 'ssh_exec' }).action).toBe(
      'allow',
    );
  });
});

describe('assertCommandPolicy', () => {
  const allowDecision = {
    action: 'allow' as const,
    code: 'policy_allowed',
    reason: 'ok',
    surface: 'ssh_exec' as const,
  };

  it('returns for allow decisions', () => {
    expect(() => assertCommandPolicy(allowDecision)).not.toThrow();
  });

  it('throws a Policy-class UsageError with code and details for deny', () => {
    try {
      assertCommandPolicy({
        action: 'deny',
        code: 'policy_denied',
        ruleId: 'rm-rf-root',
        reason: 'recursive delete',
        surface: 'ssh_exec',
      });
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(UsageError);
      expect((err as UsageError).code).toBe('policy_denied');
      expect((err as UsageError & { details?: Record<string, unknown> }).details).toMatchObject({
        action: 'deny',
        code: 'policy_denied',
        ruleId: 'rm-rf-root',
        surface: 'ssh_exec',
        reason: 'recursive delete',
      });
    }
  });

  it('throws for confirm decisions', () => {
    expect(() =>
      assertCommandPolicy({
        action: 'confirm',
        code: 'policy_confirm',
        reason: 'needs confirmation',
        surface: 'ssh_exec',
      }),
    ).toThrow(UsageError);
  });
});

function sudoConfig(overrides: Partial<Defaults['sudo']> = {}): Defaults['sudo'] {
  return { mode: 'passwordless', allow: [], deny: [], ...overrides };
}

describe('evaluateSudoPolicy', () => {
  it('denies when sudo is off', () => {
    const decision = evaluateSudoPolicy({
      command: 'ls',
      sudo: sudoConfig({ mode: 'off' }),
      surface: 'ssh_sudo',
    });
    expect(decision.action).toBe('deny');
    expect(decision.code).toBe('sudo_disabled');
  });

  it('denies in read_only command policy mode', () => {
    const decision = evaluateSudoPolicy({
      command: 'ls',
      sudo: sudoConfig(),
      surface: 'ssh_sudo',
      policyMode: 'read_only',
    });
    expect(decision.action).toBe('deny');
    expect(decision.code).toBe('policy_read_only');
  });

  it('allows passwordless/password when no rules are configured', () => {
    expect(
      evaluateSudoPolicy({ command: 'systemctl restart nginx', sudo: sudoConfig(), surface: 'ssh_sudo' })
        .action,
    ).toBe('allow');
    expect(
      evaluateSudoPolicy({
        command: 'ls',
        sudo: sudoConfig({ mode: 'password' }),
        surface: 'ssh_sudo',
      }).action,
    ).toBe('allow');
  });

  it('applies deny before allow', () => {
    const sudo = sudoConfig({
      allow: ['prefix:systemctl'],
      deny: ['prefix:systemctl status'],
    });
    expect(
      evaluateSudoPolicy({ command: 'systemctl status nginx', sudo, surface: 'ssh_sudo' }).action,
    ).toBe('deny');
    expect(
      evaluateSudoPolicy({ command: 'systemctl restart nginx', sudo, surface: 'ssh_sudo' }).action,
    ).toBe('allow');
  });

  it('denies commands outside a non-empty allow list', () => {
    const sudo = sudoConfig({ allow: ['prefix:systemctl'] });
    const decision = evaluateSudoPolicy({ command: 'rm -rf /tmp/x', sudo, surface: 'ssh_sudo' });
    expect(decision.action).toBe('deny');
    expect(decision.code).toBe('policy_not_allowed');
  });

  it('supports regex rules', () => {
    const sudo = sudoConfig({ deny: ['re:^rm\\s'] });
    expect(evaluateSudoPolicy({ command: 'rm -rf /tmp/x', sudo, surface: 'ssh_sudo' }).action).toBe(
      'deny',
    );
  });
});
