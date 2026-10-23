import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  appendAudit,
  auditFilePath,
  buildExecAuditRecord,
  maskArgv,
  sha256Hex,
} from '../../src/audit/audit.js';
import type { Logger } from '../../src/types.js';

function makeLogger(): Logger {
  const logger: Logger = {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    child: () => logger,
  };
  return logger;
}

const baseRecordInput = {
  alias: 'web1',
  destination: 'deploy@10.0.0.5:22',
  commandSha256: 'a'.repeat(64),
  commandBytes: 12,
  cwd: '~',
  envKeys: ['A', 'B'],
  stdinBytes: 3,
  timestamp: '2026-10-23T00:00:00.000Z',
};

describe('auditFilePath / sha256Hex', () => {
  it('places audit.jsonl under the config dir', () => {
    expect(auditFilePath('C:\\cfg')).toBe(path.join('C:\\cfg', 'audit.jsonl'));
  });

  it('hashes strings and buffers identically', () => {
    expect(sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
    expect(sha256Hex(Buffer.from('abc'))).toBe(sha256Hex('abc'));
  });
});

describe('maskArgv', () => {
  it('replaces only the final argument', () => {
    expect(maskArgv(['ssh', '--', 'deploy@h', 'secret cmd'], 'abc', 10)).toEqual([
      'ssh',
      '--',
      'deploy@h',
      '<redacted command sha256=abc bytes=10>',
    ]);
  });

  it('leaves an empty argv unchanged', () => {
    expect(maskArgv([], 'abc', 0)).toEqual([]);
  });

  it('does not mutate the input array', () => {
    const argv = ['ssh', 'cmd'];
    maskArgv(argv, 'abc', 3);
    expect(argv).toEqual(['ssh', 'cmd']);
  });
});

describe('buildExecAuditRecord', () => {
  it.each([
    [{ exitCode: 0 }, 'ok'],
    [{ exitCode: 7 }, 'exit_nonzero'],
    [{ exitCode: 255 }, 'transport_failure'],
    [{ exitCode: null, timedOut: true }, 'timeout'],
    [{ exitCode: null, signal: 'SIGKILL' }, 'killed'],
    [{ exitCode: null, spawnError: { code: 'ENOENT', message: 'missing' } }, 'spawn_error'],
    [{ exitCode: null }, 'spawn_error'],
  ])('derives %j as %s', (run, outcome) => {
    const record = buildExecAuditRecord({ ...baseRecordInput, run });
    expect(record.outcome).toBe(outcome);
    expect(record.tool).toBe('ssh_exec');
    expect(record.ts).toBe(baseRecordInput.timestamp);
    expect(record.commandSha256).toBe(baseRecordInput.commandSha256);
    expect(record.envKeys).toEqual(['A', 'B']);
  });

  it('uses spawn_error when nothing ran', () => {
    expect(buildExecAuditRecord(baseRecordInput).outcome).toBe('spawn_error');
  });

  it('records masked argv and queue_ms without leaking command text', () => {
    const commandText = 'curl -H "Authorization: Bearer CANARY_TOKEN"';
    const record = buildExecAuditRecord({
      ...baseRecordInput,
      run: { exitCode: 0, argv: ['ssh', '--', 'deploy@h', commandText] },
      queueMs: 17,
    });
    expect(record.queue_ms).toBe(17);
    expect(record.argv).toEqual([
      'ssh',
      '--',
      'deploy@h',
      `<redacted command sha256=${'a'.repeat(64)} bytes=12>`,
    ]);
    expect(JSON.stringify(record)).not.toContain('CANARY_TOKEN');
    expect(JSON.parse(JSON.stringify(record))).toEqual(record);
  });

  it('omits argv and queue_ms when the run facts do not provide them', () => {
    const record = buildExecAuditRecord(baseRecordInput);
    expect(record).not.toHaveProperty('argv');
    expect(record).not.toHaveProperty('queue_ms');
  });

  it('copies run facts but never records content', () => {
    const record = buildExecAuditRecord({
      ...baseRecordInput,
      run: {
        exitCode: 3,
        durationMs: 42,
        stdoutBytes: 100,
        stderrBytes: 20,
        signal: null,
        timedOut: false,
      },
      failure: { code: 'invalid_command', kind: 'Policy', message: 'CANARY_SECRET_VALUE' },
    });
    expect(record.durationMs).toBe(42);
    expect(record.stdoutBytes).toBe(100);
    expect(record.stderrBytes).toBe(20);
    expect(record.failureCode).toBe('invalid_command');
    expect(record.failureKind).toBe('Policy');
    expect(JSON.stringify(record)).not.toContain('CANARY_SECRET_VALUE');
  });
});

describe('appendAudit', () => {
  let root: string;
  let log: Logger;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-audit-'));
    log = makeLogger();
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await fs.rm(root, { recursive: true, force: true });
  });

  it('serializes 10 concurrent appends into parseable JSON lines', async () => {
    const file = auditFilePath(root);
    const records = Array.from({ length: 10 }, (_, i) =>
      buildExecAuditRecord({ ...baseRecordInput, commandBytes: i }),
    );
    await Promise.all(records.map((record) => appendAudit(record, { file, log })));

    const text = await fs.readFile(file, 'utf8');
    const lines = text.split('\n').filter((line) => line !== '');
    expect(lines).toHaveLength(10);
    const parsed = lines.map((line) => JSON.parse(line) as { commandBytes: number });
    expect(parsed.map((r) => r.commandBytes).sort((a, b) => a - b)).toEqual([
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    ]);
    expect(log.warn).not.toHaveBeenCalled();
  });

  it('never rejects when the target is unwritable', async () => {
    const blocker = path.join(root, 'not-a-dir');
    await fs.writeFile(blocker, 'x', 'utf8');
    const file = path.join(blocker, 'audit.jsonl');

    await expect(appendAudit({ ok: true }, { file, log })).resolves.toBeUndefined();
    expect(log.warn).toHaveBeenCalled();
  });

  it('never rejects for an unserializable record', async () => {
    const circular: Record<string, unknown> = {};
    circular['self'] = circular;
    await expect(appendAudit(circular, { file: auditFilePath(root), log })).resolves.toBeUndefined();
    expect(log.warn).toHaveBeenCalled();
  });
});
