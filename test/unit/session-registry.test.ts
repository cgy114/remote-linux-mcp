import { describe, expect, it } from 'vitest';
import { createSessionRegistry } from '../../src/session/registry.js';
import type { Session } from '../../src/session/session.js';
import type { CloseFacts, Snapshot } from '../../src/session/types.js';
import type { EffectiveHost } from '../../src/types.js';

const HOST: EffectiveHost = {
  alias: 'web1',
  host: 'a',
  user: 'u',
  port: 22,
  cwd: '~',
  timeouts: { connectMs: 1000, commandMs: 1000, checkMs: 1000 },
  maxOutputBytes: 1024,
  sudo: { mode: 'off', allow: [], deny: [] },
};

function expectUsageError(fn: () => unknown, code: string): void {
  let caught: unknown;
  try {
    fn();
  } catch (err) {
    caught = err;
  }
  expect(caught).toMatchObject({ name: 'UsageError', code });
}

const CLOSE_FACTS: CloseFacts = {
  exit_code: 0,
  signal: null,
  graceful: true,
  killed: false,
  duration_ms: 0,
};

function fakeSession(
  id: string,
  destination: string,
  close: (reason: string) => Promise<CloseFacts> = async () => CLOSE_FACTS,
): Session {
  const listeners: Array<(sessionId: string) => void> = [];
  const snapshot: Snapshot = {
    id,
    destination,
    state: 'ready',
    created_at: 0,
    last_activity_at: 0,
    idle_timeout_ms: 1000,
    queue_depth: 0,
    commands_run: 0,
    output_bytes: 0,
    truncated: false,
  };
  return {
    id,
    alias: 'web1',
    destination,
    host: { ...HOST, alias: 'web1' },
    cwd: '~',
    envKeys: [],
    idleTimeoutMs: 1000,
    state: 'ready',
    snapshot: () => ({ ...snapshot }),
    send: async () => {
      throw new Error('unused');
    },
    async close(reason: string): Promise<CloseFacts> {
      try {
        return await close(reason);
      } finally {
        for (const listener of listeners) listener(id);
      }
    },
    addClosedListener(listener: (sessionId: string) => void): void {
      listeners.push(listener);
    },
  };
}

describe('createSessionRegistry capacity', () => {
  it('enforces the per-destination limit and releases on abort', () => {
    const registry = createSessionRegistry({ maxGlobal: 8, maxPerDest: 1 });

    const first = registry.beginStart('u@a:22');
    expect(registry.size).toBe(1);
    expectUsageError(() => registry.beginStart('u@a:22'), 'too_many_sessions');

    first.abort();
    expect(registry.size).toBe(0);
    expect(() => registry.beginStart('u@a:22')).not.toThrow();
  });

  it('enforces the global limit across destinations', () => {
    const registry = createSessionRegistry({ maxGlobal: 2, maxPerDest: 2 });
    registry.beginStart('u@a:22');
    registry.beginStart('u@b:22');
    expectUsageError(() => registry.beginStart('u@c:22'), 'too_many_sessions');
  });

  it('commit replaces the reservation and makes the session retrievable', () => {
    const registry = createSessionRegistry({ maxGlobal: 2, maxPerDest: 1 });
    const reservation = registry.beginStart('u@a:22');
    const session = fakeSession('sess_a', 'u@a:22');

    reservation.commit(session);

    expect(registry.size).toBe(1);
    expect(registry.get('sess_a')).toBe(session);
    expect(registry.list()).toEqual([session]);
    expect(reservation.active).toBe(false);
    expectUsageError(() => registry.beginStart('u@a:22'), 'too_many_sessions');

    expect(registry.delete('sess_a')).toBe(true);
    expect(registry.delete('sess_a')).toBe(false);
    expect(() => registry.beginStart('u@a:22')).not.toThrow();
  });

  it('rejects committing an already-aborted reservation', () => {
    const registry = createSessionRegistry();
    const reservation = registry.beginStart('u@a:22');
    reservation.abort();
    expect(() => reservation.commit(fakeSession('sess_a', 'u@a:22'))).toThrow(
      /reservation is not active/,
    );
  });

  it('exposes the configured queue cap', () => {
    expect(createSessionRegistry({ maxQueue: 3 }).maxQueue).toBe(3);
    expect(createSessionRegistry().maxQueue).toBe(8);
  });

  it('removes a self-closed session from the registry and frees its slot', async () => {
    const registry = createSessionRegistry({ maxGlobal: 8, maxPerDest: 1 });
    const session = fakeSession('sess_self', 'u@a:22');
    registry.beginStart('u@a:22').commit(session);
    expect(registry.list()).toEqual([session]);

    await session.close('idle_timeout');

    expect(registry.get('sess_self')).toBeUndefined();
    expect(registry.list()).toEqual([]);
    expect(registry.size).toBe(0);
    expect(registry.delete('sess_self')).toBe(false);
    expect(() => registry.beginStart('u@a:22')).not.toThrow();
  });
});

describe('createSessionRegistry closeAll', () => {
  it('closes every session concurrently and clears the registry', async () => {
    const registry = createSessionRegistry({ maxGlobal: 4, maxPerDest: 4 });
    const reasons: string[] = [];
    for (const id of ['sess_a', 'sess_b']) {
      const reservation = registry.beginStart('u@a:22');
      reservation.commit(
        fakeSession(id, 'u@a:22', async (reason) => {
          reasons.push(reason);
          return CLOSE_FACTS;
        }),
      );
    }

    await registry.closeAll('shutdown', 1000);

    expect(reasons.sort()).toEqual(['shutdown', 'shutdown']);
    expect(registry.size).toBe(0);
    expect(registry.list()).toEqual([]);
  });

  it('resolves within the budget even when a close hangs', async () => {
    const registry = createSessionRegistry({ maxGlobal: 2, maxPerDest: 2 });
    registry.beginStart('u@a:22').commit(fakeSession('sess_hang', 'u@a:22', () => new Promise(() => undefined)));
    registry.beginStart('u@b:22').commit(fakeSession('sess_ok', 'u@b:22'));

    const started = Date.now();
    await registry.closeAll('timeout-budget', 30);
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(1000);
    expect(registry.size).toBe(0);
  });

  it('never rejects even when a session close throws', async () => {
    const registry = createSessionRegistry();
    registry.beginStart('u@a:22').commit(
      fakeSession('sess_throw', 'u@a:22', async () => {
        throw new Error('boom');
      }),
    );
    await expect(registry.closeAll('shutdown', 100)).resolves.toBeUndefined();
  });
});
