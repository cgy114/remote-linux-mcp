import { describe, expect, it } from 'vitest';
import { buildExecAuditRecord, deriveRunOutcome } from '../../src/audit/audit.js';

const baseRecordInput = {
  commandSha256: 'a'.repeat(64),
  commandBytes: 12,
};

describe('deriveRunOutcome', () => {
  it('is exported and keeps the documented mapping', () => {
    expect(typeof deriveRunOutcome).toBe('function');
    const cases: Array<[{ [k: string]: unknown }, string]> = [
      [{ exitCode: 0 }, 'ok'],
      [{ exitCode: 7 }, 'exit_nonzero'],
      [{ exitCode: 255 }, 'transport_failure'],
      [{ exitCode: null, timedOut: true }, 'timeout'],
      [{ exitCode: null, signal: 'SIGKILL' }, 'killed'],
      [{ exitCode: null, spawnError: { code: 'ENOENT', message: 'missing' } }, 'spawn_error'],
      [{ exitCode: null }, 'spawn_error'],
    ];
    for (const [run, expected] of cases) {
      expect(deriveRunOutcome({ ...baseRecordInput, run }).outcome).toBe(expected);
    }
  });

  it('treats a missing run as spawn_error with empty exit facts', () => {
    expect(deriveRunOutcome(baseRecordInput)).toEqual({
      outcome: 'spawn_error',
      exitCode: null,
      signal: null,
      timedOut: false,
    });
  });

  it('keeps the priority spawn_error > timeout > killed', () => {
    expect(
      deriveRunOutcome({
        ...baseRecordInput,
        run: { exitCode: 0, timedOut: true, spawnError: { code: 'EACCES', message: 'no' } },
      }).outcome,
    ).toBe('spawn_error');
    expect(
      deriveRunOutcome({
        ...baseRecordInput,
        run: { exitCode: 0, signal: 'SIGTERM', timedOut: true },
      }).outcome,
    ).toBe('timeout');
  });

  it('agrees with buildExecAuditRecord for every case', () => {
    const runs = [
      undefined,
      { exitCode: 0 },
      { exitCode: 3 },
      { exitCode: 255 },
      { exitCode: null, timedOut: true },
      { exitCode: null, signal: 'SIGKILL' },
      { exitCode: null, spawnError: { code: 'ENOENT', message: 'missing' } },
    ];
    for (const run of runs) {
      const input = run === undefined ? baseRecordInput : { ...baseRecordInput, run };
      expect(buildExecAuditRecord(input).outcome).toBe(deriveRunOutcome(input).outcome);
    }
  });
});
