import { describe, expect, it } from 'vitest';
import { singleFlight } from '../../src/util/inflight.js';

function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void; reject: (e: unknown) => void } {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe('singleFlight', () => {
  it('runs fn once for concurrent calls with the same key', async () => {
    let calls = 0;
    const gate = deferred<number>();
    const fn = (): Promise<number> => {
      calls++;
      return gate.promise;
    };

    const p1 = singleFlight('k', fn);
    const p2 = singleFlight('k', fn);
    const p3 = singleFlight('k', fn);
    gate.resolve(42);

    expect(await Promise.all([p1, p2, p3])).toEqual([42, 42, 42]);
    expect(calls).toBe(1);
  });

  it('does not share work across different keys', async () => {
    let calls = 0;
    const fn = async (): Promise<number> => {
      calls++;
      return calls;
    };
    await Promise.all([singleFlight('a', fn), singleFlight('b', fn)]);
    expect(calls).toBe(2);
  });

  it('removes the entry after success, so a later call runs again (no result caching)', async () => {
    let calls = 0;
    const fn = async (): Promise<number> => ++calls;
    expect(await singleFlight('ok', fn)).toBe(1);
    expect(await singleFlight('ok', fn)).toBe(2);
    expect(calls).toBe(2);
  });

  it('propagates failure to all waiters and allows retry afterwards', async () => {
    let calls = 0;
    const gate = deferred<string>();
    const failing = (): Promise<string> => {
      calls++;
      return gate.promise;
    };

    const p1 = singleFlight('f', failing);
    const p2 = singleFlight('f', failing);
    gate.reject(new Error('nope'));

    await expect(p1).rejects.toThrow('nope');
    await expect(p2).rejects.toThrow('nope');
    expect(calls).toBe(1);

    // 失败后键已删除，允许重试
    const retry = await singleFlight('f', async () => {
      calls++;
      return 'recovered';
    });
    expect(retry).toBe('recovered');
    expect(calls).toBe(2);
  });

  it('handles a synchronously throwing fn as a rejection and clears the key', async () => {
    const bad = (): Promise<never> => {
      throw new Error('sync');
    };
    await expect(singleFlight('s', bad)).rejects.toThrow('sync');
    expect(await singleFlight('s', async () => 'ok')).toBe('ok');
  });
});
