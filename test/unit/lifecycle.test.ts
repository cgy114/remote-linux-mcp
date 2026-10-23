import { EventEmitter } from 'node:events';
import { describe, expect, it, vi } from 'vitest';
import { installSignalHandlers, shutdown, sleep, withTimeout } from '../../src/lifecycle.js';
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

describe('withTimeout', () => {
  it('returns the value when the promise settles in time', async () => {
    await expect(withTimeout(Promise.resolve(42), 1000)).resolves.toEqual({ ok: true, value: 42 });
  });

  it('times out without rejecting and invokes onAbort', async () => {
    const onAbort = vi.fn();
    const never = new Promise<number>(() => undefined);
    await expect(withTimeout(never, 10, onAbort)).resolves.toEqual({ ok: false, timedOut: true });
    expect(onAbort).toHaveBeenCalledTimes(1);
  });

  it('swallows an error thrown by onAbort', async () => {
    const never = new Promise<number>(() => undefined);
    const result = await withTimeout(never, 5, () => {
      throw new Error('boom');
    });
    expect(result).toEqual({ ok: false, timedOut: true });
  });

  it('propagates the rejection of the wrapped promise', async () => {
    await expect(withTimeout(Promise.reject(new Error('inner')), 1000)).rejects.toThrow('inner');
  });
});

describe('sleep', () => {
  it('resolves after the delay', async () => {
    await expect(sleep(1)).resolves.toBeUndefined();
  });

  it('rejects with AbortError when the signal is aborted', async () => {
    const ac = new AbortController();
    const p = sleep(10_000, ac.signal);
    ac.abort();
    await expect(p).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('rejects immediately when the signal is already aborted', async () => {
    const ac = new AbortController();
    ac.abort();
    await expect(sleep(10_000, ac.signal)).rejects.toMatchObject({ name: 'AbortError' });
  });
});

describe('shutdown', () => {
  it('resolves and is idempotent (same promise on repeated calls)', async () => {
    const log = makeLogger();
    const first = shutdown({ reason: 'test', log, graceMs: 500 });
    const second = shutdown({ reason: 'again', log, graceMs: 500 });
    expect(second).toBe(first);
    await expect(first).resolves.toBeUndefined();
  });
});

describe('installSignalHandlers', () => {
  it('fires onShutdown only once and removes listeners on uninstall', () => {
    const stdin = new EventEmitter();
    const onShutdown = vi.fn();
    const uninstall = installSignalHandlers({
      onShutdown,
      stdin,
      signals: [],
    });

    stdin.emit('end');
    stdin.emit('close');
    expect(onShutdown).toHaveBeenCalledTimes(1);
    expect(onShutdown).toHaveBeenCalledWith('stdin_end');

    uninstall();
    uninstall();
    expect(stdin.listenerCount('end')).toBe(0);
    expect(stdin.listenerCount('close')).toBe(0);
  });

  it('does not propagate exceptions thrown by onShutdown', () => {
    const stdin = new EventEmitter();
    installSignalHandlers({
      onShutdown: () => {
        throw new Error('bad handler');
      },
      stdin,
      signals: [],
    });
    expect(() => stdin.emit('end')).not.toThrow();
  });
});
