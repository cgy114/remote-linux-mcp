import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { pruneAuditArchives, rotateAuditFile } from '../../../src/audit/rotation.js';
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

async function list(dir: string): Promise<string[]> {
  return (await fs.readdir(dir)).sort();
}

describe('rotateAuditFile', () => {
  let dir: string;
  let log: Logger;

  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-rotate-'));
    log = makeLogger();
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await fs.rm(dir, { recursive: true, force: true });
  });

  it('does nothing when the active file does not exist or is empty', async () => {
    const now = new Date('2026-10-24T12:00:00.000Z');
    await expect(
      rotateAuditFile({ dir, activeFile: 'audit.jsonl', now, incomingBytes: 10, maxBytes: 100, log }),
    ).resolves.toBe(false);

    await fs.writeFile(path.join(dir, 'audit.jsonl'), '', 'utf8');
    await expect(
      rotateAuditFile({ dir, activeFile: 'audit.jsonl', now, incomingBytes: 10, maxBytes: 100, log }),
    ).resolves.toBe(false);
    expect(await list(dir)).toEqual(['audit.jsonl']);
  });

  it('rotates by size and keeps the original content intact', async () => {
    const active = path.join(dir, 'audit.jsonl');
    await fs.writeFile(active, 'x'.repeat(60), 'utf8');
    const mtime = new Date('2026-10-24T08:00:00.000Z');
    await fs.utimes(active, mtime, mtime);

    const rotated = await rotateAuditFile({
      dir,
      activeFile: 'audit.jsonl',
      now: new Date('2026-10-24T12:00:00.000Z'),
      incomingBytes: 50,
      maxBytes: 100,
      log,
    });

    expect(rotated).toBe(true);
    expect(await fs.readFile(path.join(dir, 'audit-2026-10-24.jsonl'), 'utf8')).toBe(
      'x'.repeat(60),
    );
    await expect(fs.stat(active)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('does not rotate below the byte threshold on the same day', async () => {
    const active = path.join(dir, 'audit.jsonl');
    await fs.writeFile(active, 'x'.repeat(40), 'utf8');
    const mtime = new Date('2026-10-24T08:00:00.000Z');
    await fs.utimes(active, mtime, mtime);

    await expect(
      rotateAuditFile({
        dir,
        activeFile: 'audit.jsonl',
        now: new Date('2026-10-24T12:00:00.000Z'),
        incomingBytes: 50,
        maxBytes: 100,
        log,
      }),
    ).resolves.toBe(false);
    expect(await list(dir)).toEqual(['audit.jsonl']);
  });

  it('rotates on a date change even when small', async () => {
    const active = path.join(dir, 'audit.jsonl');
    await fs.writeFile(active, 'old\n', 'utf8');
    const mtime = new Date('2026-10-22T23:59:00.000Z');
    await fs.utimes(active, mtime, mtime);

    await expect(
      rotateAuditFile({
        dir,
        activeFile: 'audit.jsonl',
        now: new Date('2026-10-24T00:01:00.000Z'),
        incomingBytes: 4,
        maxBytes: 1_000_000,
        log,
      }),
    ).resolves.toBe(true);

    expect(await fs.readFile(path.join(dir, 'audit-2026-10-22.jsonl'), 'utf8')).toBe('old\n');
  });

  it('honours dateRotate=false', async () => {
    const active = path.join(dir, 'audit.jsonl');
    await fs.writeFile(active, 'old\n', 'utf8');
    const mtime = new Date('2026-10-22T23:59:00.000Z');
    await fs.utimes(active, mtime, mtime);

    await expect(
      rotateAuditFile({
        dir,
        activeFile: 'audit.jsonl',
        now: new Date('2026-10-24T00:01:00.000Z'),
        incomingBytes: 4,
        maxBytes: 1_000_000,
        dateRotate: false,
        log,
      }),
    ).resolves.toBe(false);
  });

  it('adds a numeric suffix when the archive name already exists', async () => {
    const active = path.join(dir, 'audit.jsonl');
    await fs.writeFile(active, 'second\n', 'utf8');
    await fs.writeFile(path.join(dir, 'audit-2026-10-24.jsonl'), 'first\n', 'utf8');
    const mtime = new Date('2026-10-24T08:00:00.000Z');
    await fs.utimes(active, mtime, mtime);

    await expect(
      rotateAuditFile({
        dir,
        activeFile: 'audit.jsonl',
        now: new Date('2026-10-24T12:00:00.000Z'),
        incomingBytes: 100,
        maxBytes: 10,
        log,
      }),
    ).resolves.toBe(true);

    expect(await fs.readFile(path.join(dir, 'audit-2026-10-24.jsonl'), 'utf8')).toBe('first\n');
    expect(await fs.readFile(path.join(dir, 'audit-2026-10-24.1.jsonl'), 'utf8')).toBe(
      'second\n',
    );
  });

  it('warns and keeps the active file when rename fails', async () => {
    const active = path.join(dir, 'audit.jsonl');
    await fs.writeFile(active, 'x'.repeat(60), 'utf8');
    const mtime = new Date('2026-10-24T08:00:00.000Z');
    await fs.utimes(active, mtime, mtime);
    vi.spyOn(fs, 'rename').mockRejectedValueOnce(new Error('denied'));

    await expect(
      rotateAuditFile({
        dir,
        activeFile: 'audit.jsonl',
        now: new Date('2026-10-24T12:00:00.000Z'),
        incomingBytes: 50,
        maxBytes: 100,
        log,
      }),
    ).resolves.toBe(false);
    expect(log.warn).toHaveBeenCalled();
    expect(await fs.readFile(active, 'utf8')).toBe('x'.repeat(60));
  });
});

describe('pruneAuditArchives', () => {
  let dir: string;
  let log: Logger;

  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-prune-'));
    log = makeLogger();
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await fs.rm(dir, { recursive: true, force: true });
  });

  it('deletes only strictly named archives older than retainDays', async () => {
    const names = [
      'audit-2026-07-01.jsonl', // 115 days -> delete
      'audit-2026-08-15.jsonl', // 70 days -> keep
      'audit-2026-10-24.jsonl', // today -> keep
      'audit-2026-07-01.3.jsonl', // 115 days -> delete
      'audit-notes.jsonl', // not strict -> keep
      'audit-2026-13-01.jsonl', // invalid month -> keep
      'audit.jsonl', // active -> keep
      'other.jsonl', // unrelated -> keep
    ];
    for (const name of names) await fs.writeFile(path.join(dir, name), '{}\n', 'utf8');
    await fs.mkdir(path.join(dir, 'audit-2026-06-01.jsonl'));

    const deleted = await pruneAuditArchives({
      dir,
      now: new Date('2026-10-24T00:00:00.000Z'),
      retainDays: 90,
      log,
    });

    expect(deleted.sort()).toEqual(['audit-2026-07-01.3.jsonl', 'audit-2026-07-01.jsonl']);
    expect(await list(dir)).toEqual([
      'audit-2026-06-01.jsonl',
      'audit-2026-08-15.jsonl',
      'audit-2026-10-24.jsonl',
      'audit-2026-13-01.jsonl',
      'audit-notes.jsonl',
      'audit.jsonl',
      'other.jsonl',
    ]);
    expect(log.warn).not.toHaveBeenCalled();
  });

  it('keeps an archive exactly at the retention boundary', async () => {
    // 2026-07-26T00:00:00Z + 90 days = 2026-10-24T00:00:00Z
    await fs.writeFile(path.join(dir, 'audit-2026-07-26.jsonl'), '{}\n', 'utf8');
    const deleted = await pruneAuditArchives({
      dir,
      now: new Date('2026-10-24T00:00:00.000Z'),
      retainDays: 90,
      log,
    });
    expect(deleted).toEqual([]);
  });

  it('returns quietly when the directory is missing', async () => {
    await expect(
      pruneAuditArchives({
        dir: path.join(dir, 'missing'),
        now: new Date('2026-10-24T00:00:00.000Z'),
        retainDays: 90,
        log,
      }),
    ).resolves.toEqual([]);
    expect(log.warn).not.toHaveBeenCalled();
  });
});
