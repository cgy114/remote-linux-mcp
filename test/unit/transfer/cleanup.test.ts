import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createCleanupTracker } from '../../../src/transfer/cleanup.js';

describe('cleanup tracker', () => {
  let root: string;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-cleanup-'));
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  it('removes registered local files and directories', async () => {
    const file = path.join(root, 'a.tmp');
    const dir = path.join(root, 'tree');
    await fs.writeFile(file, 'x');
    await fs.mkdir(dir);
    await fs.writeFile(path.join(dir, 'b.tmp'), 'y');

    const tracker = createCleanupTracker();
    tracker.addLocal(file);
    tracker.addRemote('/remote/.remote-mcp-tmp-0123456789abcdef');
    tracker.release(tracker.pending()[1]!);

    const report = await tracker.run();
    expect(report.removed).toBe(1);
    expect(report.failures).toEqual([]);
    expect(report.timedOut).toBe(false);
    await expect(fs.access(file)).rejects.toBeTruthy();
  });

  it('releases handles without removal', async () => {
    const file = path.join(root, 'keep.tmp');
    await fs.writeFile(file, 'x');
    const tracker = createCleanupTracker();
    const handle = tracker.addLocal(file);
    tracker.release(handle);
    const report = await tracker.run();
    expect(report.removed).toBe(0);
    await expect(fs.access(file)).resolves.toBeUndefined();
  });

  it('records failures without rejecting', async () => {
    const tracker = createCleanupTracker({
      removeLocal: async () => {
        const err = new Error('denied') as Error & { code?: string };
        err.code = 'EACCES';
        throw err;
      },
    });
    tracker.addLocal('/not/real');
    const report = await tracker.run();
    expect(report.removed).toBe(0);
    expect(report.failures).toEqual([
      { kind: 'local', path: '/not/real', code: 'EACCES', message: 'denied' },
    ]);
    expect(tracker.failures).toHaveLength(1);
  });

  it('honours the budget and marks timeouts', async () => {
    const tracker = createCleanupTracker({
      budgetMs: 25,
      removeLocal: () => new Promise<void>(() => undefined),
    });
    tracker.addLocal('/slow');
    const report = await tracker.run();
    expect(report.timedOut).toBe(true);
    expect(report.failures[0]).toMatchObject({ code: 'cleanup_timeout', path: '/slow' });
    expect(report.durationMs).toBeLessThan(1000);
  });

  it('runs only once', async () => {
    let calls = 0;
    const tracker = createCleanupTracker({
      removeLocal: async () => {
        calls += 1;
      },
    });
    tracker.addLocal('/one');
    const first = await tracker.run();
    const second = await tracker.run();
    expect(calls).toBe(1);
    expect(second).toBe(first);
  });

  it('refuses to register remote paths without the transfer temp prefix', () => {
    const tracker = createCleanupTracker();
    for (const path of ['/remote/user-file', '/remote/.remote-mcp-tmp-nothex', '/remote/.backup']) {
      expect(() => tracker.addRemote(path)).toThrow(
        expect.objectContaining({ code: 'remote_cleanup_refused' }),
      );
    }
    expect(tracker.pending()).toEqual([]);
  });

  it('fails remote cleanup when no deps or remover is provided', async () => {
    const tracker = createCleanupTracker();
    tracker.addRemote('/remote/.remote-mcp-tmp-0123456789abcdef');
    const report = await tracker.run();
    expect(report.failures[0]).toMatchObject({ kind: 'remote', path: '/remote/.remote-mcp-tmp-0123456789abcdef' });
  });

  it('delegates remote removal to the injected function', async () => {
    const removed: string[] = [];
    const tracker = createCleanupTracker({
      removeRemote: async (p) => {
        removed.push(p);
      },
    });
    tracker.addRemote('/remote/.remote-mcp-tmp-0123456789abcdef');
    const report = await tracker.run();
    expect(report.removed).toBe(1);
    expect(removed).toEqual(['/remote/.remote-mcp-tmp-0123456789abcdef']);
  });
});
