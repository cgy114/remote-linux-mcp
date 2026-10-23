import { describe, expect, it } from 'vitest';
import { ConfigError, UsageError } from '../../src/errors/classes.js';
import { policyError } from '../../src/tools/common.js';

describe('policyError', () => {
  it('uses the UsageError code and preserves the message', () => {
    expect(policyError(new UsageError('bad alias', { code: 'invalid_alias' }))).toMatchObject({
      kind: 'Policy',
      code: 'invalid_alias',
      message: 'bad alias',
    });
  });

  it('falls back to policy_denied when a UsageError carries no code', () => {
    expect(policyError(new UsageError('nope')).code).toBe('policy_denied');
  });

  it('maps ConfigError codes to config_<code>', () => {
    expect(policyError(new ConfigError('schema', 'bad')).code).toBe('config_schema');
    expect(policyError(new ConfigError('io', 'bad')).code).toBe('config_io');
  });
});
