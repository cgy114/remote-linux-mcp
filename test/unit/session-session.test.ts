import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { appendAudit } from '../../src/audit/audit.js';
import { buildSessionCloseAudit } from '../../src/session/audit.js';
import { createSessionRegistry } from '../../src/session/registry.js';
import { createSession, type CreateSessionOptions, type Session } from '../../src/session/session.js';
import type {
  SessionTransport,
  TransportCloseFacts,
  TransportEvent,
} from '../../src/session/transport.js';
import type { CloseFacts } from '../../src/session/types.js';
import type { EffectiveHost, Logger } from '../../src/types.js';

const HOST: EffectiveHost = {
  alias: 'web1',
  host: 'example.test',
  user: 'u',
  port: 22,
  cwd: '~',
  timeouts: { connectMs: 1000, commandMs: 1000, checkMs: 1000 },
  maxOutputBytes: 65_536,
  sudo: { mode: 'off', allow: [], deny: [] },
};

function makeLogger(): Logger {
  const logger: Logger = {
    debug: () => undefined,
    info: () => undefined,
    warn: () => undefined,
    error: () => undefined,
    child: () => logger,
  };
  return logger;
}

class FakeTransport implements SessionTransport {
  readonly written: string[] = [];
  closeCalls = 0;
  closeFacts: TransportCloseFacts = {
    exit_code: 0,
    signal: null,
    graceful: true,
    killed: false,
  };
  private handler: ((event: TransportEvent) => void) | undefined;
  private exitResolve: (value: { exit_code: number | null; signal: string | null }) => void =
    () => undefined;
  readonly exited = new Promise<{ exit_code: number | null; signal: string | null }>((resolve) => {
    this.exitResolve = resolve;
  });

  attach(handler: (event: TransportEvent) => void): void {
    this.handler = handler;
  }

  async writeLine(line: string): Promise<void> {
    this.written.push(line);
  }

  close(): Promise<TransportCloseFacts> {
    this.closeCalls += 1;
    this.exitResolve({ exit_code: this.closeFacts.exit_code, signal: this.closeFacts.signal });
    return Promise.resolve(this.closeFacts);
  }

  emit(event: TransportEvent): void {
    this.handler?.(event);
  }

  /** 模拟子进程意外退出（先 resolve exited，再派发 exit 事件）。 */
  die(code = 1): void {
    this.exitResolve({ exit_code: code, signal: null });
    this.emit({ type: 'exit', exit_code: code, signal: null });
  }
}

function tick(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function until(predicate: () => boolean, timeoutMs = 2000): Promise<void> {
  const started = Date.now();
  while (!predicate()) {
    if (Date.now() - started > timeoutMs) throw new Error('condition not met in time');
    await tick();
  }
}

function seqOf(line: string): number {
  return Number(line.slice(0, line.indexOf(' ')));
}

function makeSession(
  overrides: Partial<CreateSessionOptions> = {},
): { session: Session; transport: FakeTransport } {
  const transport = overrides.transport instanceof FakeTransport
    ? overrides.transport
    : new FakeTransport();
  const session = createSession({
    id: 'sess_test',
    target: {
      alias: 'web1',
      destination: 'u@example.test:22',
      host: HOST,
      defaultTimeoutMs: 1000,
      defaultMaxOutputBytes: 65_536,
    },
    transport,
    cwd: '~',
    envKeys: ['FOO'],
    idleTimeoutMs: 600_000,
    log: makeLogger(),
    ...overrides,
  });
  return { session, transport };
}

describe('createSession FIFO and framing', () => {
  it('executes commands serially with increasing seq and captures output', async () => {
    const { session, transport } = makeSession();

    const first = session.send({ command: 'echo one' });
    await until(() => transport.written.length === 1);
    expect(seqOf(transport.written[0]!)).toBe(1);

    const second = session.send({ command: 'echo two' });
    await tick();
    expect(transport.written).toHaveLength(1);

    transport.emit({ type: 'frame', frame: { type: 'B', seq: 1 } });
    transport.emit({ type: 'data', buf: Buffer.from('one\n') });
    transport.emit({ type: 'frame', frame: { type: 'E', seq: 1, rc: 0 } });

    const firstResult = await first;
    expect(firstResult.outcome.status).toBe('ok');
    if (firstResult.outcome.status !== 'ok') throw new Error('unreachable');
    expect(firstResult.outcome.seq).toBe(1);
    expect(firstResult.outcome.rc).toBe(0);
    expect(firstResult.outcome.output.text).toBe('one\n');

    await until(() => transport.written.length === 2);
    expect(seqOf(transport.written[1]!)).toBe(2);

    transport.emit({ type: 'frame', frame: { type: 'B', seq: 2 } });
    transport.emit({ type: 'data', buf: Buffer.from('two\n') });
    transport.emit({ type: 'frame', frame: { type: 'E', seq: 2, rc: 7 } });
    const secondResult = await second;
    if (secondResult.outcome.status !== 'ok') throw new Error('unreachable');
    expect(secondResult.outcome.rc).toBe(7);

    const snapshot = session.snapshot();
    expect(snapshot.commands_run).toBe(2);
    expect(snapshot.output_bytes).toBe(8);
    expect(snapshot.queue_depth).toBe(0);
    expect(snapshot.state).toBe('ready');

    await session.close();
  });

  it('redacts the handshake nonce from captured output', async () => {
    const nonce = '0123456789abcdef0123456789abcdef';
    const { session, transport } = makeSession({ nonce });
    const pending = session.send({ command: 'echo leak' });
    await until(() => transport.written.length === 1);

    transport.emit({ type: 'frame', frame: { type: 'B', seq: 1 } });
    transport.emit({ type: 'data', buf: Buffer.from(`before ${nonce} after\n`) });
    transport.emit({ type: 'frame', frame: { type: 'E', seq: 1, rc: 0 } });

    const result = await pending;
    if (result.outcome.status !== 'ok') throw new Error('unreachable');
    expect(result.outcome.output.text).toBe('before <nonce> after\n');
    expect(result.outcome.output.text).not.toContain(nonce);

    await session.close();
  });

  it('discards data outside the B..E window', async () => {
    const { session, transport } = makeSession();
    const pending = session.send({ command: 'true' });
    await until(() => transport.written.length === 1);

    transport.emit({ type: 'data', buf: Buffer.from('background noise') });
    transport.emit({ type: 'frame', frame: { type: 'B', seq: 1 } });
    transport.emit({ type: 'data', buf: Buffer.from('kept') });
    transport.emit({ type: 'frame', frame: { type: 'E', seq: 1, rc: 0 } });

    const result = await pending;
    if (result.outcome.status !== 'ok') throw new Error('unreachable');
    expect(result.outcome.output.text).toBe('kept');
    await session.close();
  });

  it('rejects with session_busy when the FIFO queue is full', async () => {
    const { session, transport } = makeSession({ maxQueue: 1 });

    const running = session.send({ command: 'one' });
    await until(() => transport.written.length === 1);
    const queued = session.send({ command: 'two' });
    await tick();

    await expect(session.send({ command: 'three' })).rejects.toMatchObject({
      code: 'session_busy',
    });

    transport.emit({ type: 'frame', frame: { type: 'B', seq: 1 } });
    transport.emit({ type: 'frame', frame: { type: 'E', seq: 1, rc: 0 } });
    await running;
    await until(() => transport.written.length === 2);
    transport.emit({ type: 'frame', frame: { type: 'B', seq: 2 } });
    transport.emit({ type: 'frame', frame: { type: 'E', seq: 2, rc: 0 } });
    await queued;

    await session.close();
  });
});

describe('createSession failures', () => {
  it('times out the command, closes the session and reports Timeout', async () => {
    const { session, transport } = makeSession({ defaultTimeoutMs: 15 });

    const pending = session.send({ command: 'sleep 999' });
    await until(() => transport.written.length === 1);

    const result = await pending;
    expect(result.outcome.status).toBe('timeout');

    await until(() => session.state === 'closed');
    expect(transport.closeCalls).toBe(1);
    await expect(session.send({ command: 'later' })).rejects.toMatchObject({
      code: 'session_closed',
    });
  });

  it('turns an unexpected transport exit into an io error and closes', async () => {
    const { session, transport } = makeSession();
    const pending = session.send({ command: 'long' });
    await until(() => transport.written.length === 1);

    transport.die(255);

    const result = await pending;
    expect(result.outcome.status).toBe('error');
    if (result.outcome.status !== 'error') throw new Error('unreachable');
    expect(result.outcome.error).toBe('io');
    await until(() => session.state === 'closed');
  });

  it('treats E without B as a protocol error and closes', async () => {
    const { session, transport } = makeSession();
    const pending = session.send({ command: 'x' });
    await until(() => transport.written.length === 1);

    transport.emit({ type: 'frame', frame: { type: 'E', seq: 1, rc: 0 } });

    const result = await pending;
    expect(result.outcome.status).toBe('error');
    if (result.outcome.status !== 'error') throw new Error('unreachable');
    expect(result.outcome.error).toBe('bad_frame');
    await until(() => session.state === 'closed');
  });

  it('treats a duplicate RDY as a protocol error', async () => {
    const { session, transport } = makeSession();
    const pending = session.send({ command: 'x' });
    await until(() => transport.written.length === 1);

    transport.emit({ type: 'frame', frame: { type: 'RDY' } });

    const result = await pending;
    expect(result.outcome.status).toBe('error');
    await until(() => session.state === 'closed');
  });

  it('closes itself after the idle timeout', async () => {
    const { session, transport } = makeSession({ idleTimeoutMs: 20 });
    expect(transport.closeCalls).toBe(0);
    await until(() => session.state === 'closed');
    expect(transport.closeCalls).toBe(1);
  });
});

describe('createSession close semantics', () => {
  it('is idempotent and settles the queue with session_closed', async () => {
    const { session, transport } = makeSession();

    const running = session.send({ command: 'one' });
    await until(() => transport.written.length === 1);
    const queued = session.send({ command: 'two' });
    await tick();

    const closing = session.close('explicit');
    await expect(queued).rejects.toMatchObject({ code: 'session_closed' });
    const runningResult = await running;
    expect(runningResult.outcome.status).toBe('closed');

    const facts = await closing;
    expect(transport.closeCalls).toBe(1);
    expect(await session.close('again')).toBe(facts);
    expect(transport.closeCalls).toBe(1);
    expect(facts.reason).toBe('explicit');
    expect(session.state).toBe('closed');
    // 无 tombstone：snapshot 不再暴露 close 事实。
    expect(session.snapshot()).not.toHaveProperty('close');
  });

  it('holds the host lease only while a command is executing', async () => {
    let active = 0;
    let maxActive = 0;
    const limiter = {
      async acquire(): Promise<{ queueMs: number; release: () => void }> {
        active += 1;
        maxActive = Math.max(maxActive, active);
        return {
          queueMs: 0,
          release: () => {
            active -= 1;
          },
        };
      },
    };

    const { session, transport } = makeSession({ limiter });
    expect(active).toBe(0);

    const first = session.send({ command: 'one' });
    await until(() => transport.written.length === 1);
    expect(active).toBe(1);

    transport.emit({ type: 'frame', frame: { type: 'B', seq: 1 } });
    transport.emit({ type: 'frame', frame: { type: 'E', seq: 1, rc: 0 } });
    await first;
    await until(() => active === 0);

    const second = session.send({ command: 'two' });
    await until(() => transport.written.length === 2);
    expect(active).toBe(1);
    transport.emit({ type: 'frame', frame: { type: 'B', seq: 2 } });
    transport.emit({ type: 'frame', frame: { type: 'E', seq: 2, rc: 0 } });
    await second;
    await until(() => active === 0);
    expect(maxActive).toBe(1);

    await session.close();
  });
});

describe('createSession closed notification', () => {
  it('invokes onClosed exactly once on explicit close', async () => {
    const calls: string[] = [];
    const { session } = makeSession({ onClosed: (sessionId) => calls.push(sessionId) });

    await session.close('explicit');
    expect(calls).toEqual(['sess_test']);

    await session.close('again');
    expect(calls).toEqual(['sess_test']);
  });

  it('invokes onClosed when a command times out', async () => {
    const calls: string[] = [];
    const { session, transport } = makeSession({
      defaultTimeoutMs: 10,
      onClosed: (sessionId) => calls.push(sessionId),
    });

    const pending = session.send({ command: 'sleep 999' });
    await until(() => transport.written.length === 1);
    expect((await pending).outcome.status).toBe('timeout');

    await until(() => session.state === 'closed');
    expect(calls).toEqual(['sess_test']);
  });

  it('invokes onClosed on a protocol error', async () => {
    const calls: string[] = [];
    const { session, transport } = makeSession({ onClosed: (sessionId) => calls.push(sessionId) });

    const pending = session.send({ command: 'x' });
    await until(() => transport.written.length === 1);
    transport.emit({ type: 'frame', frame: { type: 'E', seq: 1, rc: 0 } });
    await pending;

    await until(() => session.state === 'closed');
    expect(calls).toEqual(['sess_test']);
  });

  it('invokes onClosed when the transport exits', async () => {
    const calls: string[] = [];
    const { session, transport } = makeSession({ onClosed: (sessionId) => calls.push(sessionId) });

    transport.die(255);
    await until(() => session.state === 'closed');
    expect(calls).toEqual(['sess_test']);
  });

  it('invokes onClosed on idle timeout', async () => {
    const calls: string[] = [];
    const { session } = makeSession({
      idleTimeoutMs: 10,
      onClosed: (sessionId) => calls.push(sessionId),
    });

    await until(() => session.state === 'closed');
    expect(calls).toEqual(['sess_test']);
  });

  it('delivers the callback to listeners registered after the session closed', async () => {
    const { session } = makeSession({ idleTimeoutMs: 10 });
    await until(() => session.state === 'closed');

    const calls: string[] = [];
    session.addClosedListener((sessionId) => calls.push(sessionId));
    expect(calls).toEqual([]);
    await tick();
    expect(calls).toEqual(['sess_test']);
  });

  it('never rejects close when the callback throws', async () => {
    const { session } = makeSession({
      onClosed: () => {
        throw new Error('boom');
      },
    });

    await expect(session.close()).resolves.toBeDefined();
    expect(session.state).toBe('closed');
  });
});

describe('createSession close audit callback', () => {
  it('calls onAuditClose exactly once with the explicit reason', async () => {
    const calls: CloseFacts[] = [];
    const { session } = makeSession({
      onAuditClose: (facts) => {
        calls.push(facts);
      },
    });

    await session.close('explicit');
    await session.close('again');

    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ reason: 'explicit', graceful: true });
  });

  it('reports idle_timeout', async () => {
    const reasons: string[] = [];
    makeSession({
      idleTimeoutMs: 10,
      onAuditClose: (facts) => {
        reasons.push(facts.reason);
      },
    });

    await until(() => reasons.length === 1);
    expect(reasons).toEqual(['idle_timeout']);
  });

  it('reports command_timeout', async () => {
    const reasons: string[] = [];
    const { session, transport } = makeSession({
      defaultTimeoutMs: 10,
      onAuditClose: (facts) => {
        reasons.push(facts.reason);
      },
    });

    const pending = session.send({ command: 'sleep 999' });
    await until(() => transport.written.length === 1);
    expect((await pending).outcome.status).toBe('timeout');

    await until(() => reasons.length === 1);
    expect(reasons).toEqual(['command_timeout']);
  });

  it('reports protocol_error', async () => {
    const reasons: string[] = [];
    const { session, transport } = makeSession({
      onAuditClose: (facts) => {
        reasons.push(facts.reason);
      },
    });

    const pending = session.send({ command: 'x' });
    await until(() => transport.written.length === 1);
    transport.emit({ type: 'frame', frame: { type: 'E', seq: 1, rc: 0 } });
    await pending;

    await until(() => reasons.length === 1);
    expect(reasons).toEqual(['protocol_error']);
  });

  it('reports transport_exit', async () => {
    const reasons: string[] = [];
    const { transport } = makeSession({
      onAuditClose: (facts) => {
        reasons.push(facts.reason);
      },
    });

    transport.die(255);
    await until(() => reasons.length === 1);
    expect(reasons).toEqual(['transport_exit']);
  });

  it('swallows callback rejections and still closes', async () => {
    const { session } = makeSession({
      onAuditClose: async () => {
        throw new Error('audit backend down');
      },
    });

    await expect(session.close('explicit')).resolves.toMatchObject({ reason: 'explicit' });
    expect(session.state).toBe('closed');
  });
});

describe('createSession self-close audits', () => {
  it('writes exactly one close audit with reason/outcome for every close path', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'remote-mcp-session-audit-'));
    const file = path.join(dir, 'audit.jsonl');
    let writes = 0;

    const makeAudited = (
      id: string,
      overrides: Partial<CreateSessionOptions> = {},
    ): { session: Session; transport: FakeTransport } =>
      makeSession({
        id,
        ...overrides,
        onAuditClose: async (facts) => {
          await appendAudit(
            buildSessionCloseAudit({
              sessionId: id,
              reason: facts.reason,
              durationMs: facts.duration_ms,
              exitCode: facts.exit_code,
              signal: facts.signal,
              graceful: facts.graceful,
              killed: facts.killed,
            }),
            { file, log: makeLogger() },
          );
          writes += 1;
        },
      });

    try {
      // idle
      makeAudited('sess_audit_idle', { idleTimeoutMs: 10 });
      await until(() => writes === 1);

      // command timeout
      const timed = makeAudited('sess_audit_timeout', { defaultTimeoutMs: 10 });
      const pendingTimeout = timed.session.send({ command: 'sleep 999' });
      await until(() => timed.transport.written.length === 1);
      expect((await pendingTimeout).outcome.status).toBe('timeout');
      await until(() => writes === 2);

      // protocol error
      const protocol = makeAudited('sess_audit_protocol');
      const pendingProtocol = protocol.session.send({ command: 'x' });
      await until(() => protocol.transport.written.length === 1);
      protocol.transport.emit({ type: 'frame', frame: { type: 'E', seq: 1, rc: 0 } });
      await pendingProtocol;
      await until(() => writes === 3);

      // transport exit
      const exited = makeAudited('sess_audit_exit');
      exited.transport.die(255);
      await until(() => writes === 4);

      // explicit close, exactly once even if close() is called again
      const explicit = makeAudited('sess_audit_explicit');
      await explicit.session.close('explicit');
      expect(writes).toBe(5);
      await explicit.session.close('again');
      expect(writes).toBe(5);

      const records = (await readFile(file, 'utf8'))
        .split('\n')
        .filter((line) => line.trim().length > 0)
        .map((line) => JSON.parse(line) as Record<string, unknown>);

      expect(records).toHaveLength(5);
      expect(records.map((record) => record['reason'])).toEqual([
        'idle_timeout',
        'command_timeout',
        'protocol_error',
        'transport_exit',
        'explicit',
      ]);
      expect(records.map((record) => record['outcome'])).toEqual([
        'closed',
        'timeout',
        'error',
        'error',
        'ok',
      ]);
      for (const record of records) {
        expect(record['tool']).toBe('session_close');
      }
    } finally {
      await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }).catch(
        () => undefined,
      );
    }
  });
});

describe('createSession + registry: self-close releases capacity', () => {
  const DEST = 'u@example.test:22';

  it('removes a timed-out session and frees the per-destination slot', async () => {
    const registry = createSessionRegistry({ maxGlobal: 4, maxPerDest: 1 });
    const { session, transport } = makeSession({ id: 'sess_reg_timeout', defaultTimeoutMs: 10 });
    registry.beginStart(DEST).commit(session);
    expect(registry.list()).toHaveLength(1);

    const pending = session.send({ command: 'sleep 999' });
    await until(() => transport.written.length === 1);
    expect((await pending).outcome.status).toBe('timeout');

    await until(() => registry.list().length === 0);
    expect(registry.get('sess_reg_timeout')).toBeUndefined();
    expect(transport.closeCalls).toBe(1);
    expect(() => registry.beginStart(DEST)).not.toThrow();
  });

  it('removes a session whose transport exits unexpectedly', async () => {
    const registry = createSessionRegistry({ maxGlobal: 4, maxPerDest: 1 });
    const { session, transport } = makeSession({ id: 'sess_reg_exit' });
    registry.beginStart(DEST).commit(session);

    const pending = session.send({ command: 'long' });
    await until(() => transport.written.length === 1);
    transport.die(2);
    await pending;

    await until(() => registry.list().length === 0);
    expect(registry.get('sess_reg_exit')).toBeUndefined();
    expect(() => registry.beginStart(DEST)).not.toThrow();
  });

  it('removes a session that hits a protocol error', async () => {
    const registry = createSessionRegistry({ maxGlobal: 4, maxPerDest: 1 });
    const { session, transport } = makeSession({ id: 'sess_reg_proto' });
    registry.beginStart(DEST).commit(session);

    const pending = session.send({ command: 'x' });
    await until(() => transport.written.length === 1);
    transport.emit({ type: 'frame', frame: { type: 'E', seq: 1, rc: 0 } });
    await pending;

    await until(() => registry.list().length === 0);
    expect(registry.get('sess_reg_proto')).toBeUndefined();
    expect(() => registry.beginStart(DEST)).not.toThrow();
  });

  it('removes a session that idles out', async () => {
    const registry = createSessionRegistry({ maxGlobal: 4, maxPerDest: 1 });
    const { session } = makeSession({ id: 'sess_reg_idle', idleTimeoutMs: 10 });
    registry.beginStart(DEST).commit(session);

    await until(() => session.state === 'closed');
    await until(() => registry.list().length === 0);
    expect(registry.size).toBe(0);
  });

  it('closeAll clears the registry without errors from late removals', async () => {
    const registry = createSessionRegistry({ maxGlobal: 4, maxPerDest: 4 });
    const a = makeSession({ id: 'sess_reg_a' });
    const b = makeSession({ id: 'sess_reg_b' });
    registry.beginStart(DEST).commit(a.session);
    registry.beginStart(DEST).commit(b.session);
    expect(registry.size).toBe(2);

    await expect(registry.closeAll('shutdown', 1000)).resolves.toBeUndefined();

    expect(registry.size).toBe(0);
    expect(registry.list()).toEqual([]);
    expect(a.session.state).toBe('closed');
    expect(b.session.state).toBe('closed');
    expect(a.transport.closeCalls).toBe(1);
    expect(b.transport.closeCalls).toBe(1);
  });
});
