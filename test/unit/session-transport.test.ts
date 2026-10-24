import { spawnSync } from 'node:child_process';
import { afterEach, describe, expect, it } from 'vitest';
import { renderCwd, renderEnvExports } from '../../src/policy/remote-command.js';
import { createNonce, encodeCommandLine } from '../../src/session/frame.js';
import {
  openSessionTransport,
  SessionStartError,
  type OpenSessionTransportOptions,
  type SessionTransport,
  type TransportEvent,
} from '../../src/session/transport.js';
import type { EffectiveHost, Logger } from '../../src/types.js';

const HOST: EffectiveHost = {
  alias: 'local',
  host: '127.0.0.1',
  user: 'tester',
  port: 22,
  cwd: '~',
  timeouts: { connectMs: 5000, commandMs: 15_000, checkMs: 8000 },
  maxOutputBytes: 1024 * 1024,
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

const bashAvailable = (() => {
  try {
    const r = spawnSync('bash', ['--noprofile', '--norc', '-c', ':'], {
      timeout: 5000,
      windowsHide: true,
    });
    return !r.error && r.status === 0;
  } catch {
    return false;
  }
})();

const opened = new Set<SessionTransport>();

afterEach(async () => {
  for (const transport of [...opened]) {
    await transport.close().catch(() => undefined);
  }
  opened.clear();
});

async function open(
  overrides: Partial<OpenSessionTransportOptions> & {
    spawnOverride?: OpenSessionTransportOptions['spawnOverride'];
  } = {},
): Promise<SessionTransport> {
  const transport = await openSessionTransport({
    host: HOST,
    knownHostsFile: process.platform === 'win32' ? 'C:\\kh' : '/kh',
    nonce: createNonce(),
    cwdExpr: renderCwd('~'),
    envLines: renderEnvExports({ RMCP_TRANSPORT_TEST: '1' }),
    handshakeTimeoutMs: 5000,
    log: makeLogger(),
    spawnOverride: { file: 'bash', argv: ['--noprofile', '--norc'] },
    ...overrides,
  });
  opened.add(transport);
  return transport;
}

function attachRouter(transport: SessionTransport): {
  setHandler: (handler: (event: TransportEvent) => void) => void;
} {
  let handler: (event: TransportEvent) => void = () => undefined;
  transport.attach((event) => handler(event));
  return {
    setHandler: (next) => {
      handler = next;
    },
  };
}

interface CommandResult {
  output: string;
  rc: number;
}

function runCommand(
  transport: SessionTransport,
  router: ReturnType<typeof attachRouter>,
  seq: number,
  command: string,
  timeoutMs = 8000,
): Promise<CommandResult> {
  return new Promise<CommandResult>((resolve, reject) => {
    let started = false;
    let output = '';
    const timer = setTimeout(() => {
      router.setHandler(() => undefined);
      reject(new Error(`command ${seq} timed out`));
    }, timeoutMs);

    router.setHandler((event) => {
      if (event.type === 'data') {
        if (started) output += event.buf.toString('utf8');
        return;
      }
      if (event.type === 'parse_error') {
        clearTimeout(timer);
        router.setHandler(() => undefined);
        reject(new Error(`parse error: ${event.error}`));
        return;
      }
      if (event.type === 'exit') {
        clearTimeout(timer);
        router.setHandler(() => undefined);
        reject(new Error('transport exited'));
        return;
      }
      const frame = event.frame;
      if (frame.type === 'B' && frame.seq === seq) {
        started = true;
        return;
      }
      if (frame.type === 'E' && frame.seq === seq) {
        clearTimeout(timer);
        router.setHandler(() => undefined);
        resolve({ output, rc: frame.rc });
      }
    });

    transport.writeLine(encodeCommandLine(seq, command)).catch((err: unknown) => {
      clearTimeout(timer);
      router.setHandler(() => undefined);
      reject(err);
    });
  });
}

describe.skipIf(!bashAvailable)('openSessionTransport (local bash via spawnOverride)', () => {
  it('waits for RDY and round-trips a command', async () => {
    const transport = await open();
    const router = attachRouter(transport);

    const result = await runCommand(transport, router, 1, 'echo hello');
    expect(result.rc).toBe(0);
    expect(result.output).toBe('hello\n');

    const facts = await transport.close();
    expect(facts.graceful).toBe(true);
    expect(facts.killed).toBe(false);
  });

  it('merges remote stderr into the single output stream', async () => {
    const transport = await open();
    const router = attachRouter(transport);

    const result = await runCommand(transport, router, 1, 'echo oops >&2');
    expect(result.rc).toBe(0);
    expect(result.output).toContain('oops');
    await transport.close();
  });

  it('keeps delivering frames after the user command redirects stdout', async () => {
    const transport = await open();
    const router = attachRouter(transport);

    const first = await runCommand(transport, router, 1, 'exec >/dev/null');
    expect(first.rc).toBe(0);

    const second = await runCommand(transport, router, 2, 'echo hidden');
    expect(second.rc).toBe(0);
    expect(second.output).toBe('');

    const third = await runCommand(transport, router, 3, 'echo visible >&3');
    expect(third.rc).toBe(0);
    expect(third.output).toContain('visible');

    await transport.close();
  });

  it('closes gracefully on Q', async () => {
    const transport = await open();
    const facts = await transport.close();
    expect(facts.graceful).toBe(true);
    expect(facts.exit_code).toBe(0);
    // 幂等
    const again = await transport.close();
    expect(again).toEqual(facts);
  });

  it('fails with a handshake timeout when bash never prints RDY', async () => {
    const error = await open({
      handshakeTimeoutMs: 100,
      spawnOverride: { file: 'bash', argv: ['--noprofile', '--norc', '-c', 'sleep 10'] },
    }).catch((err: unknown) => err);

    expect(error).toBeInstanceOf(SessionStartError);
    const startError = error as SessionStartError;
    expect(startError.code).toBe('session_handshake_timeout');
    expect(startError.facts.code).toBe('session_handshake_timeout');
  });

  it('fails with session_exited_early and keeps pre-RDY diagnostics', async () => {
    const error = await open({
      spawnOverride: {
        file: 'bash',
        argv: ['--noprofile', '--norc', '-c', 'echo noise; sleep 0.3; exit 3'],
      },
    }).catch((err: unknown) => err);

    expect(error).toBeInstanceOf(SessionStartError);
    const startError = error as SessionStartError;
    expect(startError.code).toBe('session_exited_early');
    expect(startError.facts.exit_code).toBe(3);
    expect(startError.facts.pre_rdy).toContain('noise');
  });

  it('fails with session_spawn_failed for a missing executable', async () => {
    const error = await open({
      spawnOverride: { file: 'remote-mcp-no-such-binary-xyz', argv: [] },
    }).catch((err: unknown) => err);

    expect(error).toBeInstanceOf(SessionStartError);
    expect((error as SessionStartError).code).toBe('session_spawn_failed');
  });
});
