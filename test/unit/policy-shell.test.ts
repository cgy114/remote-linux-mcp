import { describe, expect, it } from 'vitest';
import { UsageError } from '../../src/errors/classes.js';
import { assertSafeText, hasLoneSurrogate, shSingleQuote } from '../../src/policy/shell.js';

function codeOf(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(UsageError);
    return (e as UsageError).code;
  }
  return undefined;
}

describe('shSingleQuote', () => {
  it('wraps plain and empty strings', () => {
    expect(shSingleQuote('abc')).toBe("'abc'");
    expect(shSingleQuote('')).toBe("''");
  });

  it('escapes embedded single quotes', () => {
    expect(shSingleQuote("a'b")).toBe("'a'\\''b'");
    expect(shSingleQuote("'")).toBe("''\\'''");
  });

  it('leaves other shell metacharacters literal inside the quotes', () => {
    expect(shSingleQuote('$HOME `id` "x" \\')).toBe(`'$HOME \`id\` "x" \\'`);
  });
});

describe('hasLoneSurrogate', () => {
  it('detects unpaired high and low surrogates', () => {
    expect(hasLoneSurrogate(String.fromCharCode(0xd800))).toBe(true);
    expect(hasLoneSurrogate(String.fromCharCode(0xdc00))).toBe(true);
    expect(hasLoneSurrogate(`a${String.fromCharCode(0xd800)}b`)).toBe(true);
  });

  it('accepts well-formed text including surrogate pairs', () => {
    expect(hasLoneSurrogate('')).toBe(false);
    expect(hasLoneSurrogate('abc')).toBe(false);
    expect(hasLoneSurrogate('中文😀')).toBe(false);
  });
});

describe('assertSafeText', () => {
  it('throws a coded UsageError for NUL', () => {
    expect(codeOf(() => assertSafeText('a\u0000b', { field: 'command', code: 'invalid_command' }))).toBe(
      'invalid_command',
    );
  });

  it('throws a coded UsageError for lone surrogates', () => {
    expect(
      codeOf(() =>
        assertSafeText(`a${String.fromCharCode(0xdc00)}`, { field: 'stdin', code: 'invalid_stdin' }),
      ),
    ).toBe('invalid_stdin');
  });

  it('accepts normal text', () => {
    expect(() => assertSafeText('echo 中文 😀\n', { field: 'command', code: 'x' })).not.toThrow();
  });
});
