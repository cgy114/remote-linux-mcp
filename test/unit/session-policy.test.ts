import { describe, expect, it } from 'vitest';
import {
  MAX_COMMAND_TIMEOUT_MS,
  MAX_IDLE_TIMEOUT_MS,
  MAX_MAX_OUTPUT_BYTES,
  MIN_COMMAND_TIMEOUT_MS,
  MIN_IDLE_TIMEOUT_MS,
  MIN_MAX_OUTPUT_BYTES,
  validateSessionSendInput,
  validateSessionStartInput,
  type SessionSendInput,
  type SessionStartInput,
} from '../../src/policy/session.js';

function codeOf(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (e) {
    return (e as { code?: string }).code ?? 'NO_CODE';
  }
  return undefined;
}

function envWith(count: number): Record<string, string> {
  const env: Record<string, string> = {};
  for (let i = 0; i < count; i++) env[`K${i}`] = 'v';
  return env;
}

describe('validateSessionStartInput', () => {
  it('accepts an empty input and all valid fields', () => {
    expect(() => validateSessionStartInput({})).not.toThrow();
    expect(() =>
      validateSessionStartInput({
        cwd: '~/work',
        env: { FOO: 'bar' },
        idle_timeout_ms: MIN_IDLE_TIMEOUT_MS,
      }),
    ).not.toThrow();
    expect(() =>
      validateSessionStartInput({ cwd: '/srv/app', idle_timeout_ms: MAX_IDLE_TIMEOUT_MS }),
    ).not.toThrow();
  });

  it('rejects invalid cwd values with invalid_cwd', () => {
    for (const cwd of ['', 'relative/path', '~user/x', '/x\n', '/x\u0000y']) {
      expect(codeOf(() => validateSessionStartInput({ cwd }))).toBe('invalid_cwd');
    }
  });

  it('rejects invalid env with invalid_env', () => {
    expect(codeOf(() => validateSessionStartInput({ env: { '1BAD': 'x' } }))).toBe('invalid_env');
    expect(codeOf(() => validateSessionStartInput({ env: { 'A-B': 'x' } }))).toBe('invalid_env');
    expect(codeOf(() => validateSessionStartInput({ env: { A: 'x\u0000y' } }))).toBe('invalid_env');
    expect(codeOf(() => validateSessionStartInput({ env: { A: '\ud800' } }))).toBe('invalid_env');
    expect(codeOf(() => validateSessionStartInput({ env: envWith(65) }))).toBe('invalid_env');
    expect(
      codeOf(() => validateSessionStartInput({ env: JSON.parse('{"__proto__":"x"}') })),
    ).toBe('invalid_env');
    expect(
      codeOf(() =>
        validateSessionStartInput({ env: { A: 'x'.repeat(16 * 1024) } }),
      ),
    ).toBe('invalid_env');
  });

  it('accepts the env entry and size boundaries', () => {
    expect(() => validateSessionStartInput({ env: envWith(64) })).not.toThrow();
    expect(() => validateSessionStartInput({ env: { A: 'x'.repeat(16 * 1024 - 1) } })).not.toThrow();
  });

  it('rejects non-object env values', () => {
    for (const env of [null, [], 'x', 42]) {
      expect(
        codeOf(() => validateSessionStartInput({ env: env as unknown as Record<string, string> })),
      ).toBe('invalid_env');
    }
  });

  it('enforces idle_timeout_ms boundaries', () => {
    expect(() => validateSessionStartInput({ idle_timeout_ms: 1_000 })).not.toThrow();
    expect(() => validateSessionStartInput({ idle_timeout_ms: 86_400_000 })).not.toThrow();
    for (const idle of [999, 86_400_001, 1000.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(codeOf(() => validateSessionStartInput({ idle_timeout_ms: idle }))).toBe(
        'invalid_idle_timeout',
      );
    }
  });

  it('rejects non-object input', () => {
    for (const input of [null, [], 'x', 42]) {
      expect(codeOf(() => validateSessionStartInput(input as unknown as SessionStartInput))).toBe(
        'invalid_session_start',
      );
    }
  });
});

describe('validateSessionSendInput', () => {
  it('accepts a minimal and a fully specified input', () => {
    expect(() => validateSessionSendInput({ command: 'echo hi' })).not.toThrow();
    expect(() =>
      validateSessionSendInput({
        command: 'echo hi',
        timeout_ms: MIN_COMMAND_TIMEOUT_MS,
        max_output_bytes: MIN_MAX_OUTPUT_BYTES,
      }),
    ).not.toThrow();
    expect(() =>
      validateSessionSendInput({
        command: 'echo hi',
        timeout_ms: MAX_COMMAND_TIMEOUT_MS,
        max_output_bytes: MAX_MAX_OUTPUT_BYTES,
      }),
    ).not.toThrow();
  });

  it('rejects empty, unsafe and oversized commands', () => {
    expect(codeOf(() => validateSessionSendInput({ command: '' }))).toBe('invalid_command');
    expect(codeOf(() => validateSessionSendInput({ command: 'a\u0000b' }))).toBe('invalid_command');
    expect(codeOf(() => validateSessionSendInput({ command: '\ud800' }))).toBe('invalid_command');
    expect(codeOf(() => validateSessionSendInput({ command: 'a'.repeat(16_385) }))).toBe(
      'command_too_large',
    );
  });

  it('accepts commands at the 16 KiB UTF-8 boundary', () => {
    expect(() => validateSessionSendInput({ command: 'a'.repeat(16_384) })).not.toThrow();
    // 5461 * 3 = 16383 bytes，再加 1 字节正好 16384。
    expect(() => validateSessionSendInput({ command: '中'.repeat(5_461) + 'a' })).not.toThrow();
    expect(() => validateSessionSendInput({ command: '中'.repeat(5_462) })).toThrow();
  });

  it('enforces timeout_ms boundaries', () => {
    expect(() => validateSessionSendInput({ command: 'x', timeout_ms: 1 })).not.toThrow();
    expect(() => validateSessionSendInput({ command: 'x', timeout_ms: 600_000 })).not.toThrow();
    for (const timeout of [0, -1, 600_001, 1.5, Number.NaN]) {
      expect(codeOf(() => validateSessionSendInput({ command: 'x', timeout_ms: timeout }))).toBe(
        'invalid_timeout',
      );
    }
  });

  it('enforces max_output_bytes boundaries', () => {
    expect(() => validateSessionSendInput({ command: 'x', max_output_bytes: 4096 })).not.toThrow();
    expect(() =>
      validateSessionSendInput({ command: 'x', max_output_bytes: 8_388_608 }),
    ).not.toThrow();
    for (const bytes of [4095, 8_388_609, 4096.5, Number.NaN]) {
      expect(codeOf(() => validateSessionSendInput({ command: 'x', max_output_bytes: bytes }))).toBe(
        'invalid_max_output',
      );
    }
  });

  it('rejects non-object input', () => {
    for (const input of [null, [], 'x', 42]) {
      expect(codeOf(() => validateSessionSendInput(input as unknown as SessionSendInput))).toBe(
        'invalid_session_send',
      );
    }
  });
});
