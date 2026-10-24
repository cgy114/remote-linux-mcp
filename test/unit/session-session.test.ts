import { describe, expect, it } from 'vitest';
import { createSession, type CreateSessionOptions, type Session } from '../../src/session/session.js';
import type {
  SessionTransport,
  TransportCloseFacts,
  TransportEvent,
} from '../../src/session/transport.js';
import type { Logger } from '../../src/types.js';

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
    expect(session.state).toBe('closed');
    expect(session.snapshot().close).toEqual(facts);
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
