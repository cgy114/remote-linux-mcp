import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  appendAuditRecord,
  auditSinkFor,
  createAuditSink,
  flushAuditSinks,
  resetAuditSinks,
} from '../../../src/audit/sink.js';
import type { Logger } from '../../../src/types.js';

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

async function readLines(file: string): Promise<Record<string, unknown>[]> {
  const text = await fs.readFile(file, 'utf8');
  return text
    .split('\n')
    .filter((line) => line !== '')
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

describe('createAuditSink', () => {
  let dir: string;
  let log: Logger;

  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-sink-'));
    log = makeLogger();
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    resetAuditSinks();
    await fs.rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  it('serializes 100 concurrent appends into parseable lines', async () => {
    const sink = createAuditSink({
      dir,
      log,
      now: () => new Date('2026-10-24T00:00:00.000Z'),
    });

    await Promise.all(
      Array.from({ length: 100 }, (_, seq) => sink.append({ seq, value: `line-${seq}` })),
    );
    await sink.flush();

    const lines = await readLines(path.join(dir, 'audit.jsonl'));
    expect(lines).toHaveLength(100);
    expect(lines.map((line) => line['seq'])).toEqual(
      Array.from({ length: 100 }, (_, i) => i),
    );
    expect(log.warn).not.toHaveBeenCalled();
  });

  it('redacts before serializing', async () => {
    const sink = createAuditSink({ dir, log });
    await sink.append({
      password: 'hunter2',
      detail: 'Authorization: Bearer abcdefghijklmnop',
      nested: { token: 'ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8' },
    });
    await sink.flush();

    const raw = await fs.readFile(path.join(dir, 'audit.jsonl'), 'utf8');
    expect(raw).not.toContain('hunter2');
    expect(raw).not.toContain('abcdefghijklmnop');
    expect(raw).not.toContain('ghp_');
    const record = JSON.parse(raw.trim()) as Record<string, unknown>;
    expect(record['password']).toBe('[REDACTED]');
    expect(record['nested']).toEqual({ token: '[REDACTED]' });
  });

  it('rotates whole lines without splitting or losing records', async () => {
    const sink = createAuditSink({
      dir,
      log,
      maxBytes: 200,
      now: () => new Date('2026-10-24T00:00:00.000Z'),
    });

    for (let seq = 0; seq < 10; seq++) {
      await sink.append({ seq, padding: 'x'.repeat(40) });
    }
    await sink.flush();

    const files = (await fs.readdir(dir)).filter((name) => name.endsWith('.jsonl')).sort();
    expect(files.length).toBeGreaterThan(1);
    let total = 0;
    for (const name of files) {
      const lines = await readLines(path.join(dir, name));
      for (const line of lines) expect(line).toHaveProperty('seq');
      total += lines.length;
    }
    expect(total).toBe(10);
    expect(log.warn).not.toHaveBeenCalled();
  });

  it('writes a single record larger than the threshold as one whole line', async () => {
    const sink = createAuditSink({
      dir,
      log,
      maxBytes: 50,
      now: () => new Date('2026-10-24T00:00:00.000Z'),
    });
    const padding = 'y'.repeat(500);
    await sink.append({ seq: 1, padding });
    await sink.flush();

    const entries = await fs.readdir(dir);
    expect(entries).toEqual(['audit.jsonl']);
    const lines = await readLines(path.join(dir, 'audit.jsonl'));
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatchObject({ seq: 1, padding });
  });

  it('never rejects when the directory cannot be created', async () => {
    const blocker = path.join(dir, 'blocker');
    await fs.writeFile(blocker, 'x', 'utf8');
    const sink = createAuditSink({ dir: path.join(blocker, 'sub'), log });

    await expect(sink.append({ ok: true })).resolves.toBeUndefined();
    await expect(sink.flush()).resolves.toBeUndefined();
    expect(log.warn).toHaveBeenCalled();
  });

  it('prunes expired archives on creation', async () => {
    await fs.writeFile(path.join(dir, 'audit-2026-01-01.jsonl'), '{}\n', 'utf8');
    const sink = createAuditSink({
      dir,
      log,
      now: () => new Date('2026-10-24T00:00:00.000Z'),
    });
    await sink.flush();

    expect(await fs.readdir(dir)).not.toContain('audit-2026-01-01.jsonl');
  });
});

describe('appendAuditRecord / auditSinkFor', () => {
  let dir: string;
  let log: Logger;

  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-sink-global-'));
    log = makeLogger();
  });

  afterEach(async () => {
    resetAuditSinks();
    await fs.rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  it('reuses one sink per config dir and flushes it', async () => {
    expect(auditSinkFor(dir, log)).toBe(auditSinkFor(dir, log));

    await appendAuditRecord({ a: 1 }, { configDir: dir, log });
    await appendAuditRecord({ a: 2 }, { configDir: dir, log });
    await flushAuditSinks();

    const lines = await readLines(path.join(dir, 'audit.jsonl'));
    expect(lines).toEqual([{ a: 1 }, { a: 2 }]);
  });

  it('keys sinks without collisions on separator-like path components', () => {
    // 若内部 key 使用可打印分隔符（如 ":::"），下面两个 (dir, file) 组合会撞 key。
    const first = auditSinkFor(dir, log, ':::audit.jsonl');
    const second = auditSinkFor(`${dir}:::`, log, 'audit.jsonl');
    expect(first).not.toBe(second);

    const firstAgain = auditSinkFor(dir, log, ':::audit.jsonl');
    expect(firstAgain).toBe(first);
  });

  it('supports a custom active file', async () => {
    await appendAuditRecord(
      { tool: 'custom' },
      { configDir: dir, log, activeFile: 'custom-audit.jsonl' },
    );
    await flushAuditSinks();
    expect(await fs.readFile(path.join(dir, 'custom-audit.jsonl'), 'utf8')).toContain('custom');
  });

  it('applies security.audit overrides passed by tool call sites', async () => {
    const audit = { maxBytes: 200, retainDays: 90, dateRotate: true };
    for (let seq = 0; seq < 8; seq++) {
      await appendAuditRecord(
        { seq, padding: 'z'.repeat(40) },
        { configDir: dir, log, audit },
      );
    }
    await flushAuditSinks();

    const archives = (await fs.readdir(dir)).filter((name) =>
      name.startsWith('audit-'),
    );
    expect(archives.length).toBeGreaterThan(0);
  });
});
