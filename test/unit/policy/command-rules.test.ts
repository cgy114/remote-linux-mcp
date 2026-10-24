import { describe, expect, it } from 'vitest';
import { ConfigError } from '../../../src/errors/classes.js';
import { BUILTIN_RULE_DEFS, builtinReason } from '../../../src/policy/command-defaults.js';
import {
  builtinCommandRules,
  compileCommandPolicy,
  isForbiddenProgram,
  isSensitiveEnvKey,
  parseRule,
  rulePrefixTokens,
} from '../../../src/policy/command-rules.js';

function configErrorCode(fn: () => unknown): string | undefined {
  try {
    fn();
    return undefined;
  } catch (err) {
    expect(err).toBeInstanceOf(ConfigError);
    return (err as ConfigError).code;
  }
}

describe('parseRule', () => {
  it('compiles re: rules without anchoring', () => {
    const rule = parseRule('re:rm\\s+-rf', 'config', 'r1');
    expect(rule.kind).toBe('re');
    expect(rule.regex?.test('xxx rm -rf /')).toBe(true);
    expect(rule.regex?.test('rm -rf /')).toBe(true);
  });

  it('parses prefix: rules into canonical token form', () => {
    const rule = parseRule('prefix:  systemctl   status ', 'config', 'r2');
    expect(rule.kind).toBe('prefix');
    expect(rule.prefix).toBe('systemctl status');
    expect(rulePrefixTokens(rule)).toEqual(['systemctl', 'status']);
  });

  it('treats a bare spec as a prefix rule', () => {
    const rule = parseRule('ls -la', 'config', 'r3');
    expect(rule.kind).toBe('prefix');
    expect(rulePrefixTokens(rule)).toEqual(['ls', '-la']);
  });

  it('rejects invalid regexes', () => {
    expect(configErrorCode(() => parseRule('re:[', 'config', 'bad'))).toBe('schema');
  });

  it('rejects empty rules and empty prefix/regex bodies', () => {
    expect(configErrorCode(() => parseRule('', 'config', 'empty'))).toBe('schema');
    expect(configErrorCode(() => parseRule('   ', 'config', 'blank'))).toBe('schema');
    expect(configErrorCode(() => parseRule('prefix:', 'config', 'p'))).toBe('schema');
    expect(configErrorCode(() => parseRule('re:', 'config', 'r'))).toBe('schema');
  });

  it('rejects non-string rules', () => {
    expect(configErrorCode(() => parseRule(42 as unknown, 'config', 'n'))).toBe('schema');
  });
});

describe('compileCommandPolicy', () => {
  it('fills enforce + useDefaultDeny defaults and merges builtin rules', () => {
    const policy = compileCommandPolicy({});
    expect(policy.mode).toBe('enforce');
    expect(policy.useDefaultDeny).toBe(true);
    expect(policy.allow).toEqual([]);
    expect(policy.confirm).toEqual([]);
    expect(policy.deny.length).toBe(BUILTIN_RULE_DEFS.length);
    expect(policy.deny.every((rule) => rule.source === 'builtin')).toBe(true);
  });

  it('honors use_default_deny=false and keeps config rules with ids', () => {
    const policy = compileCommandPolicy({
      use_default_deny: false,
      allow: ['prefix:ls'],
      confirm: ['re:systemctl\\s+restart'],
      deny: ['prefix:rm -rf'],
    });
    expect(policy.deny).toHaveLength(1);
    expect(policy.deny[0]?.source).toBe('config');
    expect(policy.deny[0]?.id).toBe('deny[0]');
    expect(policy.allow[0]?.id).toBe('allow[0]');
    expect(policy.confirm[0]?.kind).toBe('re');
  });
});

describe('builtin rules', () => {
  it('contains at least 30 rules, each with id and Chinese reason', () => {
    expect(BUILTIN_RULE_DEFS.length).toBeGreaterThanOrEqual(30);
    for (const def of BUILTIN_RULE_DEFS) {
      expect(def.id).toMatch(/^[a-z0-9.-]+$/);
      expect(def.reason.length).toBeGreaterThan(0);
      expect(builtinReason(def.id)).toBe(def.reason);
    }
    const ids = new Set(BUILTIN_RULE_DEFS.map((def) => def.id));
    expect(ids.size).toBe(BUILTIN_RULE_DEFS.length);
  });

  it('marks interpreters, wrappers and privilege programs hard', () => {
    const rules = builtinCommandRules();
    for (const id of ['hard-sudo', 'hard-su', 'hard-bash', 'hard-sh', 'hard-python', 'hard-env']) {
      expect(rules.find((rule) => rule.id === id)?.hard).toBe(true);
    }
  });
});

describe('isSensitiveEnvKey', () => {
  it.each([
    'PATH',
    'BASH_ENV',
    'ENV',
    'LD_PRELOAD',
    'LD_LIBRARY_PATH',
    'LD_AUDIT',
    'SHELLOPTS',
    'BASHOPTS',
    'IFS',
    'CDPATH',
    'GLOBIGNORE',
    'PROMPT_COMMAND',
    'PS4',
    'GIT_SSH_COMMAND',
    'GIT_PAGER',
    'PAGER',
    'SSH_ASKPASS',
    'DISPLAY',
  ])('flags %s', (key) => {
    expect(isSensitiveEnvKey(key)).toBe(true);
  });

  it.each(['FOO', 'path', 'HOME', 'TERM'])('does not flag %s', (key) => {
    expect(isSensitiveEnvKey(key)).toBe(false);
  });
});

describe('isForbiddenProgram', () => {
  it.each(['sudo', 'bash', 'python3', 'env', 'xargs', 'find', 'sed', 'tar', 'rsync', 'ssh', 'docker', 'eval', 'source', '.', 'trap'])(
    'flags %s',
    (program) => {
      expect(isForbiddenProgram(program)).toBe(true);
    },
  );

  it('matches by basename', () => {
    expect(isForbiddenProgram('/bin/bash')).toBe(true);
    expect(isForbiddenProgram('/usr/bin/sudo')).toBe(true);
  });

  it.each(['ls', 'cat', 'grep', 'df', 'systemctl', 'rm'])('does not flag %s', (program) => {
    expect(isForbiddenProgram(program)).toBe(false);
  });
});
