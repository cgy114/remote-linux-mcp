import { describe, expect, it } from 'vitest';
import { createHostLimiter, getDefaultHostLimiter } from '../../src/ssh/host-limiter.js';

describe('createHostLimiter', () => {
  it('caps active tasks per key, completes all tasks, and releases on throw', async () => {
    const limit = 4;
    const limiter = createHostLimiter(limit);
    const keys = ['alpha', 'beta', 'gamma'] as const;

    const active = new Map<string, number>();
    const maxActive = new Map<string, number>();
    let completed = 0;
    let thrown = 0;

    const tasks = keys.flatMap((key) =>
      Array.from({ length: 7 }, (_, index) =>
        (async () => {
          const lease = await limiter.acquire(key);
          expect(lease.queueMs).toBeGreaterThanOrEqual(0);
          const now = (active.get(key) ?? 0) + 1;
          active.set(key, now);
          maxActive.set(key, Math.max(maxActive.get(key) ?? 0, now));
          try {
            await new Promise((resolve) => setTimeout(resolve, 5));
            if (index === 3) throw new Error('simulated failure');
            completed++;
          } finally {
            active.set(key, (active.get(key) ?? 1) - 1);
            lease.release();
            lease.release(); // 幂等
          }
        })().catch(() => {
          thrown++;
        }),
      ),
    );

    await Promise.all(tasks);

    for (const key of keys) {
      expect(maxActive.get(key)).toBeLessThanOrEqual(limit);
      expect(active.get(key)).toBe(0);
    }
    expect(completed).toBe(18);
    expect(thrown).toBe(3);
  });

  it('grants same-key leases in FIFO order', async () => {
    const limiter = createHostLimiter(1);
    const first = await limiter.acquire('k');
    const order: number[] = [];
    const waiting = [0, 1, 2].map((n) =>
      limiter.acquire('k').then((lease) => {
        order.push(n);
        lease.release();
      }),
    );
    first.release();
    await Promise.all(waiting);
    expect(order).toEqual([0, 1, 2]);
  });

  it('does not serialize across different keys', async () => {
    const limiter = createHostLimiter(1);
    const a = await limiter.acquire('a');
    const b = await limiter.acquire('b');
    expect(b.queueMs).toBeGreaterThanOrEqual(0);
    a.release();
    b.release();
  });

  it('rejects non-positive limits', () => {
    expect(() => createHostLimiter(0)).toThrow();
    expect(() => createHostLimiter(-1)).toThrow();
    expect(() => createHostLimiter(1.5)).toThrow();
  });
});

describe('getDefaultHostLimiter', () => {
  it('returns the same instance with a limit of 4', async () => {
    const limiter = getDefaultHostLimiter();
    expect(limiter).toBe(getDefaultHostLimiter());

    const held = await Promise.all([0, 1, 2, 3].map(() => limiter.acquire('singleton-key')));
    let fifthGranted = false;
    const fifth = limiter.acquire('singleton-key').then((lease) => {
      fifthGranted = true;
      lease.release();
    });
    await Promise.resolve();
    expect(fifthGranted).toBe(false);
    for (const lease of held) lease.release();
    await fifth;
    expect(fifthGranted).toBe(true);
  });
});
