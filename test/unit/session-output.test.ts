import { describe, expect, it } from 'vitest';
import { createOutputCapture } from '../../src/session/output.js';
import type { CapturedOutput } from '../../src/session/types.js';

function run(chunks: Array<string | Buffer | Uint8Array>, maxBytes: number): CapturedOutput {
  const capture = createOutputCapture(maxBytes);
  for (const chunk of chunks) {
    capture.push(typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk);
  }
  return capture.finish();
}

describe('createOutputCapture', () => {
  it('returns small ASCII output unchanged', () => {
    expect(run(['hello'], 100)).toEqual({
      text: 'hello',
      encoding: 'utf-8',
      truncated: false,
      bytes: 5,
    });
  });

  it('returns an empty result for no input', () => {
    expect(run([], 16)).toEqual({ text: '', encoding: 'utf-8', truncated: false, bytes: 0 });
  });

  it('does not truncate when total equals maxBytes', () => {
    const r = run(['a'.repeat(10)], 10);
    expect(r).toEqual({ text: 'aaaaaaaaaa', encoding: 'utf-8', truncated: false, bytes: 10 });
  });

  it('keeps head and tail when total exceeds maxBytes', () => {
    const r = run(['ABCDEFGHIJKLMNOPQRST'], 10);
    expect(r.truncated).toBe(true);
    expect(r.bytes).toBe(20);
    expect(r.text).toBe('ABCDEPQRST');
    expect(r.encoding).toBe('utf-8');
  });

  it('counts total bytes while retaining a bounded head and tail', () => {
    const chunks = Array.from({ length: 100 }, () => Buffer.from('0123456789'));
    const r = run(chunks, 20);
    expect(r.bytes).toBe(1000);
    expect(r.truncated).toBe(true);
    expect(r.text).toBe('01234567890123456789');
  });

  it('compacts the tail across many tiny chunks', () => {
    const input = '0123456789'.repeat(100);
    const r = run([...input], 10);
    expect(r.bytes).toBe(1000);
    expect(r.text).toBe('0123456789');
  });

  it('preserves multi-byte UTF-8 without truncation', () => {
    const text = '中文输出😀🚀';
    const r = run([text], 1024);
    expect(r.text).toBe(text);
    expect(r.encoding).toBe('utf-8');
  });

  it('never splits a multi-byte character at the truncation seam', () => {
    const text = '中😀'.repeat(40);
    const input = Buffer.from(text, 'utf8');
    for (let max = 1; max <= 80; max++) {
      const r = run([input], max);
      expect(r.truncated).toBe(true);
      expect(r.bytes).toBe(input.length);
      expect(r.encoding).toBe('utf-8');
      expect(r.text).not.toContain('�');
      expect(Buffer.byteLength(r.text, 'utf8')).toBeLessThanOrEqual(max);
    }
  });

  it('keeps complete characters on both sides of the seam', () => {
    const r = run(['A' + '😀'.repeat(5) + 'B'], 10);
    expect(r.truncated).toBe(true);
    expect(r.encoding).toBe('utf-8');
    expect(r.text).toBe('A😀😀B');
  });

  it('preserves ANSI escape sequences byte-for-byte', () => {
    const text = '\u001b[31mred\u001b[0m\u001b[1;32mgreen\u001b[0m\n';
    const r = run([text], 1024);
    expect(r.encoding).toBe('utf-8');
    expect(r.text).toBe(text);
  });

  it('falls back to base64 for binary content', () => {
    const input = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe]);
    const r = run([input], 1024);
    expect(r.encoding).toBe('base64');
    expect(Buffer.from(r.text, 'base64').equals(input)).toBe(true);
    expect(r.truncated).toBe(false);
  });

  it('uses base64 when NUL appears even in valid UTF-8', () => {
    const input = Buffer.from('a\u0000b', 'utf8');
    const r = run([input], 1024);
    expect(r.encoding).toBe('base64');
    expect(Buffer.from(r.text, 'base64').equals(input)).toBe(true);
  });

  it('uses base64 for invalid UTF-8 without NUL', () => {
    const input = Buffer.from([0xc3, 0x28, 0x41]);
    const r = run([input], 1024);
    expect(r.encoding).toBe('base64');
    expect(Buffer.from(r.text, 'base64').equals(input)).toBe(true);
  });

  it('truncates binary content while still reporting total bytes', () => {
    const input = Buffer.alloc(500, 0xff);
    const r = run([input], 100);
    expect(r.encoding).toBe('base64');
    expect(r.truncated).toBe(true);
    expect(r.bytes).toBe(500);
    const kept = Buffer.from(r.text, 'base64');
    expect(kept.length).toBeGreaterThan(0);
    expect(kept.length).toBeLessThanOrEqual(100);
  });

  it('accepts non-Buffer Uint8Array chunks', () => {
    const r = run([new Uint8Array([0x61, 0x62, 0x63])], 16);
    expect(r.text).toBe('abc');
  });

  it('ignores empty chunks but keeps counting later data', () => {
    const capture = createOutputCapture(16);
    capture.push(Buffer.alloc(0));
    capture.push(new Uint8Array(0));
    capture.push(Buffer.from('xy'));
    expect(capture.finish().text).toBe('xy');
  });

  it('exposes byte count and truncation before finish', () => {
    const capture = createOutputCapture(4);
    expect(capture.bytes).toBe(0);
    expect(capture.truncated).toBe(false);
    capture.push(Buffer.from('abc'));
    expect(capture.bytes).toBe(3);
    expect(capture.truncated).toBe(false);
    capture.push(Buffer.from('de'));
    expect(capture.bytes).toBe(5);
    expect(capture.truncated).toBe(true);
  });

  it('is idempotent on finish and rejects pushes afterwards', () => {
    const capture = createOutputCapture(16);
    capture.push(Buffer.from('abc'));
    const first = capture.finish();
    expect(capture.finish()).toBe(first);
    expect(() => capture.push(Buffer.from('d'))).toThrow(/finished/);
  });

  it('rejects invalid maxBytes', () => {
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => createOutputCapture(bad)).toThrow(RangeError);
    }
  });

  it('works with tiny limits', () => {
    for (const max of [1, 2, 3]) {
      const r = run(['abcdef'], max);
      expect(r.truncated).toBe(true);
      expect(r.bytes).toBe(6);
      expect(Buffer.byteLength(r.text, 'utf8')).toBeLessThanOrEqual(max);
    }
  });
});
