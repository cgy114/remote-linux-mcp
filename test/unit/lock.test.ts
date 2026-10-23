import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { TrustError } from '../../src/errors/classes.js';
import { withFileLock } from '../../src/util/lock.js';

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

describe('withFileLock', () => {
  let root: string;
  let lockFile: string;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-lock-'));
    lockFile = path.join(root, 'trust.lock');
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  it('serializes two concurrent critical sections', async () => {
    const events: string[] = [];
    const a = withFileLock(lockFile, async () => {
      events.push('a-start');
      await sleep(150);
      events.push('a-end');
      return 'a';
    });
    const b = withFileLock(lockFile, async () => {
      events.push('b-start');
      await sleep(10);
      events.push('b-end');
      return 'b';
    });

    // 返回值顺序与调用顺序一致，与谁先拿到锁无关
    expect(await Promise.all([a, b])).toEqual(['a', 'b']);
    // 谁先拿到锁不确定，但临界区不交错：只允许两种完整的串行顺序
    expect([
      ['a-start', 'a-end', 'b-start', 'b-end'],
      ['b-start', 'b-end', 'a-start', 'a-end'],
    ]).toContainEqual(events);
  });

  it('removes the lock file after fn completes (also on failure)', async () => {
    await withFileLock(lockFile, async () => 1);
    await expect(fs.stat(lockFile)).rejects.toThrow();

    await expect(
      withFileLock(lockFile, async () => {
        throw new Error('inner');
      }),
    ).rejects.toThrow('inner');
    await expect(fs.stat(lockFile)).rejects.toThrow();
  });

  it('writes { pid, time } into the lock file while held', async () => {
    await withFileLock(lockFile, async () => {
      const raw = await fs.readFile(lockFile, 'utf8');
      const parsed = JSON.parse(raw) as { pid: number; time: string };
      expect(parsed.pid).toBe(process.pid);
      expect(typeof parsed.time).toBe('string');
    });
  });

  it('throws TrustError lock_busy when the lock is held past timeoutMs', async () => {
    const holder = withFileLock(lockFile, async () => {
      await sleep(400);
    });
    await sleep(20);

    const err = await withFileLock(lockFile, async () => 'never', { timeoutMs: 150 }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TrustError);
    expect((err as TrustError).code).toBe('lock_busy');

    await holder;
  });

  it('reclaims a stale lock file (mtime older than staleMs)', async () => {
    await fs.writeFile(lockFile, JSON.stringify({ pid: 999999, time: 'old' }), 'utf8');
    const old = new Date(Date.now() - 60_000);
    await fs.utimes(lockFile, old, old);

    const result = await withFileLock(lockFile, async () => 'reclaimed', { staleMs: 30_000, timeoutMs: 1000 });
    expect(result).toBe('reclaimed');
    await expect(fs.stat(lockFile)).rejects.toThrow();
  });

  it('does not reclaim a fresh lock file that is not yet stale', async () => {
    await fs.writeFile(lockFile, JSON.stringify({ pid: 1, time: 'now' }), 'utf8');
    await expect(
      withFileLock(lockFile, async () => 'x', { staleMs: 60_000, timeoutMs: 120 }),
    ).rejects.toMatchObject({ code: 'lock_busy' });
  });
});
