import { describe, expect, it } from 'vitest';
import {
  buildSessionCloseAudit,
  buildSessionSendAudit,
  buildSessionStartAudit,
  deriveSessionCloseOutcome,
  deriveSessionSendOutcome,
} from '../../src/session/audit.js';

describe('session audit builders', () => {
  it('records start identity without nonce or env values', () => {
    const record = buildSessionStartAudit({
      sessionId: 'sess_abc',
      alias: 'web1',
      destination: 'u@example.test:22',
      cwd: '~/work',
      envKeys: ['FOO', 'PATH'],
      idleTimeoutMs: 900_000,
    });
    expect(record).toMatchObject({
      tool: 'session_start',
      session_id: 'sess_abc',
      alias: 'web1',
      destination: 'u@example.test:22',
      cwd: '~/work',
      envKeys: ['FOO', 'PATH'],
      idle_timeout_ms: 900_000,
      outcome: 'ok',
    });
    const serialized = JSON.stringify(record);
    expect(serialized).not.toContain('nonce');
    expect(serialized).not.toContain('SECRET_VALUE');
  });

  it('marks failed starts with failure code/kind but no message', () => {
    const record = buildSessionStartAudit({
      alias: 'web1',
      failure: { code: 'not_registered', kind: 'HostKey' },
    });
    expect(record.outcome).toBe('failed');
    expect(record.failureCode).toBe('not_registered');
    expect(record.failureKind).toBe('HostKey');
    expect(record).not.toHaveProperty('session_id');
  });

  it('summarizes a send with hashes, byte counts and timings only', () => {
    const record = buildSessionSendAudit({
      sessionId: 'sess_abc',
      alias: 'web1',
      destination: 'u@example.test:22',
      cwd: '~',
      seq: 3,
      commandSha256: 'a'.repeat(64),
      commandBytes: 11,
      exitCode: 2,
      outputBytes: 512,
      truncated: false,
      durationMs: 40,
      queueMs: 5,
      sessionQueueMs: 7,
    });
    expect(record).toMatchObject({
      tool: 'session_send',
      session_id: 'sess_abc',
      seq: 3,
      commandSha256: 'a'.repeat(64),
      commandBytes: 11,
      exitCode: 2,
      outputBytes: 512,
      truncated: false,
      durationMs: 40,
      queue_ms: 5,
      session_queue_ms: 7,
      outcome: 'exit_nonzero',
    });
    const serialized = JSON.stringify(record);
    expect(serialized).not.toContain('echo');
    expect(serialized).not.toContain('stdout');
  });

  it('derives send outcomes with failure priority', () => {
    const base = {
      sessionId: 's',
      commandSha256: 'x',
      commandBytes: 1,
    };
    expect(deriveSessionSendOutcome({ ...base })).toBe('ok');
    expect(deriveSessionSendOutcome({ ...base, exitCode: 1 })).toBe('exit_nonzero');
    expect(
      deriveSessionSendOutcome({ ...base, failure: { code: 'session_timeout', kind: 'Timeout' } }),
    ).toBe('timeout');
    expect(
      deriveSessionSendOutcome({ ...base, failure: { code: 'unknown_session', kind: 'Policy' } }),
    ).toBe('denied');
    expect(
      deriveSessionSendOutcome({ ...base, failure: { code: 'session_io_error', kind: 'Internal' } }),
    ).toBe('error');
  });

  it('records close facts without command or output content', () => {
    const record = buildSessionCloseAudit({
      sessionId: 'sess_abc',
      alias: 'web1',
      destination: 'u@example.test:22',
      cwd: '~',
      envKeys: ['FOO'],
      commandsRun: 4,
      outputBytes: 2048,
      truncated: true,
      durationMs: 60_000,
      exitCode: 0,
      signal: null,
      graceful: true,
      killed: false,
    });
    expect(record).toMatchObject({
      tool: 'session_close',
      session_id: 'sess_abc',
      commandsRun: 4,
      outputBytes: 2048,
      truncated: true,
      durationMs: 60_000,
      exitCode: 0,
      graceful: true,
      killed: false,
      outcome: 'ok',
    });
    expect(JSON.stringify(record)).not.toContain('secret');
  });

  it('records the close reason and derives self-close outcomes', () => {
    const cases: Array<[string, string]> = [
      ['explicit', 'ok'],
      ['idle_timeout', 'closed'],
      ['shutdown', 'closed'],
      ['command_timeout', 'timeout'],
      ['protocol_error', 'error'],
      ['transport_exit', 'error'],
      ['trust_revoked', 'denied'],
    ];
    for (const [reason, outcome] of cases) {
      expect(deriveSessionCloseOutcome({ sessionId: 's', reason })).toBe(outcome);
      expect(buildSessionCloseAudit({ sessionId: 's', reason })).toMatchObject({
        tool: 'session_close',
        reason,
        outcome,
      });
    }
  });
});
