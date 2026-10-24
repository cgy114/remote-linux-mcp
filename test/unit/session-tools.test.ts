import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createSessionRegistry, type SessionRegistry } from '../../src/session/registry.js';
import type { Session } from '../../src/session/session.js';
import type { CloseFacts, SendOutcome, Snapshot } from '../../src/session/types.js';
import { sessionClose, sessionCloseInput } from '../../src/tools/session-close.js';
import {
  SESSION_CLOSE_ANNOTATIONS,
  SESSION_LIST_ANNOTATIONS,
  SESSION_SEND_ANNOTATIONS,
  SESSION_START_ANNOTATIONS,
  useSessionRegistry,
} from '../../src/tools/session-common.js';
import { sessionList, sessionListInput } from '../../src/tools/session-list.js';
import { sessionSend, sessionSendInput } from '../../src/tools/session-send.js';
import { sessionStart, sessionStartInput } from '../../src/tools/session-start.js';
import type { ToolContext } from '../../src/tools/common.js';
import type { Logger, MCPPaths, RemoteConfig } from '../../src/types.js';

const CLOSE_FACTS: CloseFacts = {
  exit_code: 0,
  signal: null,
  graceful: true,
  killed: false,
  duration_ms: 123,
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

function makeFiles(): RemoteConfig['files'] {
  return {
    localRoots: [],
    remoteDeny: [],
    maxFileBytes: 1,
    maxFiles: 1,
    maxTotalBytes: 1,
    maxDepth: 0,
    transferTimeoutMs: 1000,
  };
}

function makeConfig(dir: string): RemoteConfig {
  return {
    version: 1,
    sourcePath: path.join(dir, 'config.yaml'),
    baseDir: dir,
    defaults: {
      port: 22,
      defaultCwd: '~',
      timeouts: { connectMs: 1000, commandMs: 1000, checkMs: 1000 },
      maxOutputBytes: 1024 * 1024,
      sudo: { mode: 'off', allow: [], deny: [] },
      files: makeFiles(),
    },
    security: { hostKeyPolicy: 'pinned' },
    hosts: { web1: { host: '127.0.0.1', user: 'tester' } },
    files: makeFiles(),
  };
}

function makePaths(dir: string): MCPPaths {
  return {
    configFile: path.join(dir, 'config.yaml'),
    configDir: dir,
    knownHostsFile: path.join(dir, 'known_hosts'),
    trustRegistryFile: path.join(dir, 'trust.json'),
    trustLockFile: path.join(dir, 'trust.lock'),
    source: 'flag',
  };
}

function makeCtx(dir: string, config?: RemoteConfig): ToolContext {
  return {
    paths: makePaths(dir),
    log: makeLogger(),
    getConfig: async () => {
      if (config === undefined) throw new Error('config must not be read');
      return config;
    },
  };
}

function makeFakeSession(options: {
  id?: string;
  alias?: string;
  destination?: string;
  send?: Session['send'];
  close?: Session['close'];
  snapshot?: Partial<Snapshot>;
} = {}): Session {
  const id = options.id ?? 'sess_fake';
  const destination = options.destination ?? 'tester@example.test:22';
  const listeners: Array<(sessionId: string) => void> = [];
  const closeImpl: Session['close'] = options.close ?? (async () => CLOSE_FACTS);
  const snapshot: Snapshot = {
    id,
    destination,
    state: 'ready',
    created_at: 1,
    last_activity_at: 2,
    idle_timeout_ms: 900_000,
    queue_depth: 0,
    commands_run: 0,
    output_bytes: 0,
    truncated: false,
    ...options.snapshot,
  };
  return {
    id,
    alias: options.alias ?? 'web1',
    destination,
    cwd: '~',
    envKeys: ['FOO'],
    idleTimeoutMs: 900_000,
    state: 'ready',
    snapshot: () => ({ ...snapshot }),
    send: options.send ?? (async () => {
      throw new Error('send should not be called');
    }),
    async close(reason?: string): Promise<CloseFacts> {
      try {
        return await closeImpl(reason);
      } finally {
        for (const listener of listeners) listener(id);
      }
    },
    addClosedListener(listener: (sessionId: string) => void): void {
      listeners.push(listener);
    },
  };
}

function register(registry: SessionRegistry, session: Session): void {
  registry.beginStart(session.destination).commit(session);
}

async function readAudit(dir: string): Promise<Array<Record<string, unknown>>> {
  try {
    const text = await readFile(path.join(dir, 'audit.jsonl'), 'utf8');
    return text
      .split('\n')
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
  } catch {
    return [];
  }
}

const tempDirs = new Set<string>();

async function makeTempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'remote-mcp-session-tools-'));
  tempDirs.add(dir);
  return dir;
}

beforeEach(() => {
  useSessionRegistry(createSessionRegistry());
});

afterEach(async () => {
  useSessionRegistry(undefined);
  for (const dir of tempDirs) {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }).catch(
      () => undefined,
    );
  }
  tempDirs.clear();
});

describe('session tool schemas', () => {
  it('are strict and bound their fields', () => {
    expect(sessionStartInput.safeParse({}).success).toBe(true);
    expect(sessionStartInput.safeParse({ unknown: true }).success).toBe(false);
    expect(sessionStartInput.safeParse({ idle_timeout_ms: 10 }).success).toBe(false);
    expect(sessionStartInput.safeParse({ idle_timeout_ms: 1000 }).success).toBe(true);

    expect(sessionSendInput.safeParse({ session_id: 's', command: 'echo' }).success).toBe(true);
    expect(sessionSendInput.safeParse({ session_id: 's' }).success).toBe(false);
    expect(
      sessionSendInput.safeParse({ session_id: 's', command: 'x', timeout_ms: 0 }).success,
    ).toBe(false);
    expect(
      sessionSendInput.safeParse({ session_id: 's', command: 'x', extra: 1 }).success,
    ).toBe(false);

    expect(sessionCloseInput.safeParse({ session_id: 's' }).success).toBe(true);
    expect(sessionCloseInput.safeParse({ session_id: 's', force: true }).success).toBe(false);

    expect(sessionListInput.safeParse({}).success).toBe(true);
    expect(sessionListInput.safeParse({ host: 'x' }).success).toBe(false);
  });
});

describe('session tool annotations', () => {
  it('match the documented hints', () => {
    expect(SESSION_START_ANNOTATIONS).toEqual({
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    });
    expect(SESSION_SEND_ANNOTATIONS).toEqual({
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    });
    expect(SESSION_CLOSE_ANNOTATIONS).toEqual({
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    });
    expect(SESSION_LIST_ANNOTATIONS).toEqual({ readOnlyHint: true });
  });
});

describe('session_start', () => {
  it('rejects untrusted hosts before reserving or spawning', async () => {
    const dir = await makeTempDir();
    const registry = createSessionRegistry();
    useSessionRegistry(registry);

    const result = await sessionStart({ host: 'web1' }, makeCtx(dir, makeConfig(dir)));

    expect(result.isError).toBe(true);
    const structured = result.structuredContent as {
      error: { kind: string; code: string };
    };
    expect(structured.error.kind).toBe('HostKey');
    expect(structured.error.code).toBe('host_key');
    expect(registry.size).toBe(0);
  });

  it('rejects invalid input without reading the config', async () => {
    const dir = await makeTempDir();
    const result = await sessionStart({ cwd: 'relative/path' }, makeCtx(dir));

    expect(result.isError).toBe(true);
    const structured = result.structuredContent as {
      error: { kind: string; code: string };
    };
    expect(structured.error.kind).toBe('Policy');
    expect(structured.error.code).toBe('invalid_cwd');
  });
});

describe('session_send', () => {
  it('returns output + timings and writes one hash-only audit record', async () => {
    const dir = await makeTempDir();
    const registry = createSessionRegistry();
    useSessionRegistry(registry);
    const outcome: SendOutcome = {
      status: 'ok',
      seq: 4,
      rc: 0,
      output: { text: 'hello\n', encoding: 'utf-8', truncated: false, bytes: 6 },
      duration_ms: 12,
    };
    register(
      registry,
      makeFakeSession({
        send: async () => ({ outcome, queueMs: 3, sessionQueueMs: 5 }),
      }),
    );

    const result = await sessionSend(
      { session_id: 'sess_fake', command: 'echo hello' },
      makeCtx(dir),
    );

    expect(result.isError).toBe(false);
    expect(result.structuredContent).toMatchObject({
      tool: 'session_send',
      session_id: 'sess_fake',
      host: 'web1',
      exit_code: 0,
      output: 'hello\n',
      encoding: 'utf-8',
      bytes: 6,
      truncated: false,
      duration_ms: 12,
      queue_ms: 3,
      session_queue_ms: 5,
    });

    const audit = await readAudit(dir);
    expect(audit).toHaveLength(1);
    const record = audit[0]!;
    expect(record).toMatchObject({
      tool: 'session_send',
      session_id: 'sess_fake',
      outcome: 'ok',
      exitCode: 0,
      commandBytes: 10,
      commandSha256: createHash('sha256').update('echo hello').digest('hex'),
    });
    expect(JSON.stringify(record)).not.toContain('echo hello');
  });

  it('reports unknown sessions as Policy', async () => {
    const dir = await makeTempDir();
    const result = await sessionSend({ session_id: 'sess_missing', command: 'true' }, makeCtx(dir));

    expect(result.isError).toBe(true);
    const structured = result.structuredContent as {
      error: { kind: string; code: string };
    };
    expect(structured.error).toMatchObject({ kind: 'Policy', code: 'unknown_session' });
    expect(await readAudit(dir)).toHaveLength(0);
  });

  it('maps a timeout outcome to a Timeout tool error and audits it', async () => {
    const dir = await makeTempDir();
    const registry = createSessionRegistry();
    useSessionRegistry(registry);
    const outcome: SendOutcome = {
      status: 'timeout',
      seq: 1,
      output: { text: '', encoding: 'utf-8', truncated: false, bytes: 0 },
      duration_ms: 30,
    };
    register(
      registry,
      makeFakeSession({ send: async () => ({ outcome, queueMs: 0, sessionQueueMs: 0 }) }),
    );

    const result = await sessionSend(
      { session_id: 'sess_fake', command: 'sleep 99' },
      makeCtx(dir),
    );

    expect(result.isError).toBe(true);
    const structured = result.structuredContent as {
      error: { kind: string; code: string };
    };
    expect(structured.error).toMatchObject({ kind: 'Timeout', code: 'session_timeout' });

    const audit = await readAudit(dir);
    expect(audit[0]).toMatchObject({
      tool: 'session_send',
      outcome: 'timeout',
      failureKind: 'Timeout',
      failureCode: 'session_timeout',
    });
  });
});

describe('session_close', () => {
  it('closes, removes from the registry and audits the facts', async () => {
    const dir = await makeTempDir();
    const registry = createSessionRegistry();
    useSessionRegistry(registry);
    const reasons: string[] = [];
    register(
      registry,
      makeFakeSession({
        close: async (reason) => {
          reasons.push(reason);
          return CLOSE_FACTS;
        },
      }),
    );

    const result = await sessionClose({ session_id: 'sess_fake' }, makeCtx(dir));

    expect(result.isError).toBe(false);
    expect(result.structuredContent).toMatchObject({
      tool: 'session_close',
      session_id: 'sess_fake',
      exit_code: 0,
      graceful: true,
      killed: false,
      duration_ms: 123,
    });
    expect(reasons).toEqual(['explicit']);
    expect(registry.get('sess_fake')).toBeUndefined();

    const audit = await readAudit(dir);
    expect(audit[0]).toMatchObject({
      tool: 'session_close',
      session_id: 'sess_fake',
      outcome: 'ok',
      graceful: true,
    });
  });

  it('reports unknown sessions as Policy', async () => {
    const dir = await makeTempDir();
    const result = await sessionClose({ session_id: 'sess_missing' }, makeCtx(dir));

    expect(result.isError).toBe(true);
    const structured = result.structuredContent as {
      error: { kind: string; code: string };
    };
    expect(structured.error).toMatchObject({ kind: 'Policy', code: 'unknown_session' });
  });
});

describe('session_list', () => {
  it('returns snapshots without commands, output or nonce and writes no audit', async () => {
    const dir = await makeTempDir();
    const registry = createSessionRegistry();
    useSessionRegistry(registry);
    register(
      registry,
      makeFakeSession({
        id: 'sess_one',
        snapshot: { commands_run: 3, output_bytes: 42, truncated: true, state: 'ready' },
      }),
    );
    register(
      registry,
      makeFakeSession({
        id: 'sess_two',
        destination: 'tester@other.test:22',
        snapshot: { state: 'busy', queue_depth: 2 },
      }),
    );

    const result = await sessionList({}, makeCtx(dir));

    expect(result.isError).toBe(false);
    const structured = result.structuredContent as {
      tool: string;
      count: number;
      sessions: Array<Record<string, unknown>>;
    };
    expect(structured.tool).toBe('session_list');
    expect(structured.count).toBe(2);
    expect(structured.sessions).toHaveLength(2);
    for (const entry of structured.sessions) {
      expect(Object.keys(entry).sort()).toEqual(
        [
          'commands_run',
          'created_at',
          'destination',
          'host',
          'idle_timeout_ms',
          'last_activity_at',
          'output_bytes',
          'queue_depth',
          'session_id',
          'state',
          'truncated',
        ].sort(),
      );
    }
    expect(JSON.stringify(structured)).not.toContain('nonce');
    expect(await readAudit(dir)).toHaveLength(0);
  });

  it('reports an empty registry', async () => {
    const dir = await makeTempDir();
    const result = await sessionList({}, makeCtx(dir));
    expect(result.isError).toBe(false);
    expect(result.structuredContent).toMatchObject({ count: 0, sessions: [] });
  });
});
