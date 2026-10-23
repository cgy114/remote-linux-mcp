import { describe, expect, it } from 'vitest';
import {
  buildTransferAuditRecord,
  deriveTransferOutcome,
  type TransferAuditInput,
} from '../../../src/audit/transfer-audit.js';

function input(overrides: Partial<TransferAuditInput> = {}): TransferAuditInput {
  return {
    direction: 'upload',
    alias: 'web1',
    destination: 'deploy@10.0.0.5:22',
    sourcePath: 'C:\\local\\a.txt',
    targetPath: '~/a.txt',
    files: 1,
    bytes: 3,
    run: { exitCode: 0, durationMs: 10, stdoutBytes: 0, stderrBytes: 0 },
    ...overrides,
  };
}

describe('transfer audit', () => {
  describe('deriveTransferOutcome', () => {
    it('covers every category and priority', () => {
      expect(deriveTransferOutcome(input())).toBe('ok');
      expect(deriveTransferOutcome(input({ verified: true }))).toBe('verified');
      expect(
        deriveTransferOutcome(input({ failure: { kind: 'Policy', code: 'remote_denied_write' } })),
      ).toBe('denied');
      expect(
        deriveTransferOutcome(input({ run: { timedOut: true }, failure: { kind: 'Policy' } })),
      ).toBe('denied');
      expect(deriveTransferOutcome(input({ run: { timedOut: true, exitCode: null } }))).toBe('timeout');
      expect(
        deriveTransferOutcome(input({ run: { exitCode: null, spawnError: true } })),
      ).toBe('spawn_failed');
      expect(
        deriveTransferOutcome(input({ failure: { kind: 'Internal', code: 'local_io_error' } })),
      ).toBe('spawn_failed');
      expect(
        deriveTransferOutcome(input({ run: { exitCode: 0 }, failure: { code: 'verify_sha256_mismatch' } })),
      ).toBe('verify_failed');
      expect(deriveTransferOutcome(input({ run: { exitCode: 255 } }))).toBe('transport_failure');
      expect(deriveTransferOutcome(input({ run: { exitCode: null, signal: 'SIGKILL' } }))).toBe(
        'transport_failure',
      );
      expect(deriveTransferOutcome(input({ run: { exitCode: 2 } }))).toBe('remote_exit');
    });
  });

  describe('buildTransferAuditRecord', () => {
    it('records transfer facts and failure metadata only', () => {
      const record = buildTransferAuditRecord(
        input({
          timestamp: '2026-10-23T00:00:00.000Z',
          tool: 'file_upload',
          verified: true,
          run: { exitCode: 1, signal: null, timedOut: false, durationMs: 42 },
          failure: { kind: 'RemoteExit', code: 'remote_exit', message: 'SECRET OUTPUT' } as never,
        }),
      );
      expect(record).toEqual({
        ts: '2026-10-23T00:00:00.000Z',
        tool: 'file_upload',
        alias: 'web1',
        destination: 'deploy@10.0.0.5:22',
        direction: 'upload',
        sourcePath: 'C:\\local\\a.txt',
        targetPath: '~/a.txt',
        files: 1,
        bytes: 3,
        outcome: 'remote_exit',
        exitCode: 1,
        signal: null,
        timedOut: false,
        durationMs: 42,
        verified: true,
        failureCode: 'remote_exit',
        failureKind: 'RemoteExit',
      });
      const serialized = JSON.stringify(record);
      expect(serialized).not.toContain('SECRET');
      expect(serialized).not.toContain('message');
    });

    it('defaults missing counters and tool name', () => {
      const record = buildTransferAuditRecord({
        direction: 'download',
        timestamp: '2026-10-23T00:00:00.000Z',
      });
      expect(record).toMatchObject({
        tool: 'file_transfer',
        files: 0,
        bytes: 0,
        outcome: 'ok',
        exitCode: null,
        signal: null,
        timedOut: false,
      });
      expect(record.failureCode).toBeUndefined();
    });

    it('omits optional fields when absent', () => {
      const record = buildTransferAuditRecord({
        direction: 'remote_copy',
        timestamp: '2026-10-23T00:00:00.000Z',
        run: { exitCode: 0 },
      });
      expect(Object.keys(record)).not.toContain('alias');
      expect(Object.keys(record)).not.toContain('durationMs');
      expect(Object.keys(record)).not.toContain('verified');
    });
  });
});
