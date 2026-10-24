import { describe, expect, it } from 'vitest';
import type { RunResult } from '../../../src/types.js';
import {
  buildSftpBatch,
  chmodStep,
  getStep,
  putStep,
  quoteSftpPath,
  sftpDiagnostics,
} from '../../../src/transfer/sftp.js';

function run(overrides: Partial<RunResult> = {}): RunResult {
  return {
    argv: [],
    displayCommand: 'sftp',
    exitCode: 0,
    signal: null,
    stdout: '',
    stderr: '',
    stdoutBytes: 0,
    stderrBytes: 0,
    stdoutTruncated: false,
    stderrTruncated: false,
    timedOut: false,
    durationMs: 1,
    ...overrides,
  };
}

describe('sftp', () => {
  describe('quoteSftpPath', () => {
    it('quotes spaces and ordinary characters', () => {
      expect(quoteSftpPath('/home/u/a b.txt')).toBe('"/home/u/a b.txt"');
      expect(quoteSftpPath('plain')).toBe('"plain"');
    });

    it('escapes quotes and backslashes', () => {
      expect(quoteSftpPath('a"b')).toBe('"a\\"b"');
      expect(quoteSftpPath('a\\b')).toBe('"a\\\\b"');
      expect(quoteSftpPath('a"\\b')).toBe('"a\\"\\\\b"');
    });

    it('preserves non-ASCII and shell metacharacters literally', () => {
      expect(quoteSftpPath('~/ü $x `y`')).toBe('"~/ü $x `y`"');
    });

    it('rejects empty and unsafe values', () => {
      for (const value of ['', 'a\nb', 'a\rb', 'a\u0000b', `a${String.fromCharCode(0xd800)}b`]) {
        expect(() => quoteSftpPath(value)).toThrow(
          expect.objectContaining({ code: 'remote_path_invalid' }),
        );
      }
    });
  });

  describe('steps', () => {
    it('builds put/get with local path normalization', () => {
      const local = process.platform === 'win32' ? 'C:\\tmp\\a b.txt' : '/tmp/a b.txt';
      const expectedLocal = process.platform === 'win32' ? '"C:/tmp/a b.txt"' : '"/tmp/a b.txt"';
      expect(putStep(local, '/home/u/a b.txt')).toBe(`put ${expectedLocal} "/home/u/a b.txt"`);
      expect(getStep('/home/u/a b.txt', local)).toBe(`get "/home/u/a b.txt" ${expectedLocal}`);
    });

    it('builds chmod', () => {
      expect(chmodStep(0o755, '/a')).toBe('chmod 755 "/a"');
      expect(chmodStep('640', '/a')).toBe('chmod 640 "/a"');
      expect(chmodStep(0o100644, '/a')).toBe('chmod 644 "/a"');
      expect(chmodStep(0o1000, '/a')).toBe('chmod 0 "/a"');
      expect(() => chmodStep('abc', '/a')).toThrow(
        expect.objectContaining({ code: 'remote_path_invalid' }),
      );
    });
  });

  describe('buildSftpBatch', () => {
    it('joins steps with one trailing newline', () => {
      expect(buildSftpBatch(['put "/a" "/b"', 'rename "/b" "/c"'])).toBe(
        'put "/a" "/b"\nrename "/b" "/c"\n',
      );
      expect(buildSftpBatch([])).toBe('');
    });

    it('never emits a bare newline inside a step', () => {
      expect(() => buildSftpBatch(['put "/a\nb" "/c"'])).toThrow(
        expect.objectContaining({ code: 'remote_path_invalid' }),
      );
      expect(() => buildSftpBatch([''])).toThrow(
        expect.objectContaining({ code: 'remote_path_invalid' }),
      );
    });
  });

  describe('sftpDiagnostics', () => {
    it('reports common failures without throwing', () => {
      expect(
        sftpDiagnostics(
          run({
            exitCode: 1,
            stderr: 'remote open("/root/x"): Permission denied\nFailure',
          }),
        ),
      ).toEqual(
        expect.arrayContaining(['permission denied on the remote path', 'sftp reported a failure']),
      );
      expect(sftpDiagnostics(run({ exitCode: 1, stderr: 'open: No such file or directory' }))).toContain(
        'remote path not found',
      );
      expect(sftpDiagnostics(run({ timedOut: true, exitCode: null }))).toContain('sftp timed out');
      expect(
        sftpDiagnostics(
          run({ exitCode: 1, stderr: 'Connection closed by 10.0.0.5 port 22' }),
        ),
      ).toContain('ssh transport problem');
      expect(sftpDiagnostics(run({ exitCode: 3, stderr: '' }))).toEqual(['sftp exited with code 3']);
    });
  });
});
