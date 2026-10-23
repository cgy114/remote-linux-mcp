import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ConfigError, TrustError } from '../../src/errors/classes.js';
import { fingerprintKey } from '../../src/trust/fingerprint.js';
import { acquireTrustLock, loadTrustRegistry, saveTrustRegistry } from '../../src/trust/registry.js';
import type { PinnedHostKey, TrustRegistry } from '../../src/types.js';

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function pin(seed: string): PinnedHostKey {
  const keyBlob = Buffer.from(`registry-test-${seed}`).toString('base64');
  return {
    algorithm: 'ssh-ed25519',
    keyBlob,
    fingerprint: fingerprintKey(keyBlob),
    firstSeenAt: '2026-01-01T00:00:00.000Z',
    lastVerifiedAt: '2026-01-02T00:00:00.000Z',
  };
}

describe('trust registry load/save', () => {
  let dir: string;
  let file: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-reg-'));
    file = path.join(dir, 'trust', 'registry.json');
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it('missing file -> empty registry', async () => {
    expect(await loadTrustRegistry(file)).toEqual({ version: 1, hosts: {} });
  });

  it('corrupt JSON -> ConfigError parse', async () => {
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file, '{ not json', 'utf8');
    await expect(loadTrustRegistry(file)).rejects.toMatchObject({ name: 'ConfigError', code: 'parse' });
    await expect(loadTrustRegistry(file)).rejects.toBeInstanceOf(ConfigError);
  });

  it('version !== 1 -> ConfigError schema', async () => {
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file, JSON.stringify({ version: 2, hosts: {} }), 'utf8');
    await expect(loadTrustRegistry(file)).rejects.toMatchObject({ code: 'schema' });
  });

  it('rejects structural problems with schema: hosts not object, missing fields, extra fields, bad fingerprint', async () => {
    await fs.mkdir(path.dirname(file), { recursive: true });
    const good = pin('x');
    const cases: unknown[] = [
      { version: 1, hosts: [] },
      { version: 1 },
      { version: 1, hosts: {}, extra: true },
      { version: 1, hosts: { h1: { ...good, fingerprint: undefined } } },
      { version: 1, hosts: { h1: { ...good, extra: 1 } } },
      { version: 1, hosts: { h1: { ...good, fingerprint: 'MD5:abc' } } },
      { version: 1, hosts: { h1: { ...good, fingerprint: 'SHA256:AAAA' } } },
      { version: 1, hosts: { 'bad alias!': good } },
    ];
    for (const c of cases) {
      await fs.writeFile(file, JSON.stringify(c), 'utf8');
      await expect(loadTrustRegistry(file), JSON.stringify(c)).rejects.toMatchObject({
        name: 'ConfigError',
        code: 'schema',
      });
    }
  });

  it('save then load returns an equal registry', async () => {
    const reg: TrustRegistry = { version: 1, hosts: { 'web-1': pin('a'), 'db-1': pin('b') } };
    await saveTrustRegistry(file, reg);
    expect(await loadTrustRegistry(file)).toEqual(reg);
    const text = await fs.readFile(file, 'utf8');
    expect(text.endsWith('\n')).toBe(true);
    expect(text).toBe(JSON.stringify(reg, null, 2) + '\n');
  });

  it('save rejects an invalid registry without touching the file', async () => {
    await expect(
      saveTrustRegistry(file, { version: 1, hosts: { h: { ...pin('c'), algorithm: '' } } } as TrustRegistry),
    ).rejects.toMatchObject({ code: 'schema' });
    await expect(fs.stat(file)).rejects.toThrow();
  });
});

describe('acquireTrustLock', () => {
  let dir: string;
  let lock: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-tlock-'));
    lock = path.join(dir, 'trust.lock');
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it('serializes two concurrent holders', async () => {
    const events: string[] = [];
    const first = await acquireTrustLock(lock);
    events.push('a-held');
    const second = acquireTrustLock(lock, { timeoutMs: 2000 }).then(async (rel) => {
      events.push('b-held');
      await rel();
    });
    await sleep(120);
    expect(events).toEqual(['a-held']);
    events.push('a-release');
    await first();
    await second;
    expect(events).toEqual(['a-held', 'a-release', 'b-held']);
  });

  it('writes { pid, time } while held and removes the file on release', async () => {
    const release = await acquireTrustLock(lock);
    const body = JSON.parse(await fs.readFile(lock, 'utf8')) as { pid: number; time: string };
    expect(body.pid).toBe(process.pid);
    expect(Number.isNaN(Date.parse(body.time))).toBe(false);
    await release();
    await expect(fs.stat(lock)).rejects.toThrow();
  });

  it('times out with TrustError lock_busy when held elsewhere', async () => {
    const holder = await acquireTrustLock(lock, { staleMs: 60_000 });
    try {
      await expect(acquireTrustLock(lock, { timeoutMs: 200, staleMs: 60_000 })).rejects.toBeInstanceOf(TrustError);
      await expect(acquireTrustLock(lock, { timeoutMs: 200, staleMs: 60_000 })).rejects.toMatchObject({
        code: 'lock_busy',
      });
    } finally {
      await holder();
    }
  });

  it('reclaims a stale lock file', async () => {
    await fs.writeFile(lock, '{"pid":1,"time":"old"}', 'utf8');
    const old = new Date(Date.now() - 120_000);
    await fs.utimes(lock, old, old);
    const release = await acquireTrustLock(lock, { staleMs: 1000, timeoutMs: 500 });
    await release();
  });

  it('release is idempotent and does not delete a lock taken by someone else', async () => {
    const release = await acquireTrustLock(lock);
    await release();
    await expect(release()).resolves.toBeUndefined();

    const next = await acquireTrustLock(lock);
    await release(); // 第一次的 release 再次调用，不应删除新持有者的锁
    await expect(fs.stat(lock)).resolves.toBeDefined();
    await next();
  });

  it('release leaves a lock file whose token belongs to another holder', async () => {
    const release = await acquireTrustLock(lock);
    const foreign = JSON.stringify({ pid: 999_999, token: 'foreign-token', time: new Date().toISOString() });
    await fs.writeFile(lock, foreign, 'utf8');
    await release();
    expect(await fs.readFile(lock, 'utf8')).toBe(foreign);
  });

  it('reclaims a stale lock atomically and removes both the lock and the temp name', async () => {
    const stale = JSON.stringify({ pid: 1, token: 'old-token', time: '2000-01-01T00:00:00.000Z' });
    await fs.writeFile(lock, stale, 'utf8');
    const old = new Date(Date.now() - 120_000);
    await fs.utimes(lock, old, old);

    const release = await acquireTrustLock(lock, { staleMs: 1000, timeoutMs: 1000 });
    const body = JSON.parse(await fs.readFile(lock, 'utf8')) as { pid: number; token: string };
    expect(body.pid).toBe(process.pid);
    expect(body.token).not.toBe('old-token');
    expect((await fs.readdir(dir)).filter((n) => n.includes('.reclaim-'))).toEqual([]);
    await release();
    await expect(fs.stat(lock)).rejects.toThrow();
  });

  it('lets exactly one of two racing acquires win; the other reports lock_busy', async () => {
    const settled = await Promise.allSettled([
      acquireTrustLock(lock, { staleMs: 60_000, timeoutMs: 300 }),
      acquireTrustLock(lock, { staleMs: 60_000, timeoutMs: 300 }),
    ]);
    const fulfilled = settled.filter(
      (s): s is PromiseFulfilledResult<() => Promise<void>> => s.status === 'fulfilled',
    );
    const rejected = settled.filter(
      (s): s is PromiseRejectedResult => s.status === 'rejected',
    );
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect(rejected[0]?.reason).toMatchObject({ name: 'TrustError', code: 'lock_busy' });
    await fulfilled[0]?.value();
  });
});
