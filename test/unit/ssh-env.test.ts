import os from 'node:os';
import { describe, expect, it } from 'vitest';
import { assertEnvSafe, buildChildEnv } from '../../src/ssh/env.js';

describe('buildChildEnv', () => {
  it('fills ProgramData when base lacks it', () => {
    const env = buildChildEnv({ base: { PATH: 'x' } });
    expect(env.ProgramData).toBe('C:\\ProgramData');
    expect(env.SystemRoot).toBe('C:\\Windows');
    expect(env.USERPROFILE).toBe(os.homedir());
    expect(env.TEMP).toBe(os.tmpdir());
    expect(env.TMP).toBe(os.tmpdir());
  });

  it('keeps existing ProgramData and PATH', () => {
    const env = buildChildEnv({ base: { ProgramData: 'D:\\PD', PATH: 'P' } });
    expect(env.ProgramData).toBe('D:\\PD');
    expect(env.PATH).toBe('P');
  });

  it('strips DISPLAY, SSH_ASKPASS and GIT_SSH* variables', () => {
    const env = buildChildEnv({
      base: {
        DISPLAY: ':0',
        SSH_ASKPASS: 'askpass',
        GIT_SSH: 'g',
        GIT_SSH_COMMAND: 'gc',
        GIT_SSH_VARIANT: 'v',
      },
    });
    expect(env).not.toHaveProperty('DISPLAY');
    expect(env).not.toHaveProperty('SSH_ASKPASS');
    expect(env).not.toHaveProperty('GIT_SSH');
    expect(env).not.toHaveProperty('GIT_SSH_COMMAND');
    expect(env).not.toHaveProperty('GIT_SSH_VARIANT');
  });

  it('sets SSH_ASKPASS_REQUIRE, LC_ALL and LANG', () => {
    const env = buildChildEnv({ base: { LC_ALL: 'en_US.UTF-8', LANG: 'en' } });
    expect(env.SSH_ASKPASS_REQUIRE).toBe('never');
    expect(env.LC_ALL).toBe('C');
    expect(env.LANG).toBe('C');
  });

  it('passes agentSocket through as SSH_AUTH_SOCK', () => {
    expect(buildChildEnv({ base: {}, agentSocket: '\\\\.\\pipe\\agent' }).SSH_AUTH_SOCK).toBe(
      '\\\\.\\pipe\\agent',
    );
  });

  it('preserves SSH_AUTH_SOCK from base when no agentSocket is given', () => {
    expect(buildChildEnv({ base: { SSH_AUTH_SOCK: 'orig' } }).SSH_AUTH_SOCK).toBe('orig');
  });

  it('does not mutate the base object', () => {
    const base: NodeJS.ProcessEnv = { DISPLAY: ':0', PATH: 'p' };
    const snapshot = { ...base };
    const env = buildChildEnv({ base, agentSocket: 's' });
    expect(base).toEqual(snapshot);
    expect(env).not.toBe(base);
  });
});

describe('assertEnvSafe', () => {
  const safe = (): NodeJS.ProcessEnv => buildChildEnv({ base: { ProgramData: 'C:\\PD' } });

  it('accepts a built child env', () => {
    expect(() => assertEnvSafe(safe())).not.toThrow();
  });

  it('rejects DISPLAY and SSH_ASKPASS with code unsafe_env', () => {
    for (const key of ['DISPLAY', 'SSH_ASKPASS']) {
      const env = { ...safe(), [key]: 'x' };
      try {
        assertEnvSafe(env);
        expect.unreachable();
      } catch (err) {
        expect((err as { code?: string }).code).toBe('unsafe_env');
        expect((err as { kind?: string }).kind).toBe('Internal');
      }
    }
  });

  it('rejects SSH_ASKPASS_REQUIRE other than never', () => {
    expect(() => assertEnvSafe({ ...safe(), SSH_ASKPASS_REQUIRE: 'force' })).toThrow(/unsafe/);
  });

  it('rejects missing or empty ProgramData', () => {
    const env = safe();
    delete env.ProgramData;
    expect(() => assertEnvSafe(env)).toThrow(/ProgramData/);
    expect(() => assertEnvSafe({ ...safe(), ProgramData: '' })).toThrow(/ProgramData/);
  });
});
