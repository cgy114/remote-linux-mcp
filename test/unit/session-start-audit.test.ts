import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createSessionRegistry } from '../../src/session/registry.js';
import type {
  SessionTransport,
  TransportCloseFacts,
  TransportEvent,
} from '../../src/session/transport.js';
import { fingerprintKey } from '../../src/trust/fingerprint.js';
import type { ToolContext } from '../../src/tools/common.js';
import { useSessionRegistry } from '../../src/tools/session-common.js';
import { sessionClose } from '../../src/tools/session-close.js';
import { sessionStart } from '../../src/tools/session-start.js';
import type { Logger, MCPPaths, RemoteConfig } from '../../src/types.js';

/** sessionStart 只能通过模块函数建立传输；这里注入一个本地 FakeTransport。 */
const bridge = vi.hoisted(() => ({
  transport: undefined as unknown,
  openCalls: 0,
}));

vi.mock('../../src/session/transport.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/session/transport.js')>();
  return {
    ...actual,
    openSessionTransport: vi.fn(async () => {
      bridge.openCalls += 1;
      return bridge.transport;
    }),
  };
});

class FakeTransport implements SessionTransport {
  preRdyDiagnostic = '';
  stderrDiagnostic = '';
  private handler: ((event: TransportEvent) => void) | undefined;
  private exitResolve: (value: { exit_code: number | null; signal: string | null }) => void =
    () => undefined;
  readonly exited = new Promise<{ exit_code: number | null; signal: string | null }>(
    (resolve) => {
      this.exitResolve = resolve;
    },
  );

  attach(handler: (event: TransportEvent) => void): void {
    this.handler = handler;
  }

  async writeLine(): Promise<void> {
    // 会话审计测试不执行真实命令。
  }

  close(): Promise<TransportCloseFacts> {
    this.exitResolve({ exit_code: 0, signal: null });
    return Promise.resolve({ exit_code: 0, signal: null, graceful: true, killed: false });
  }

  /** 模拟远端进程意外退出。 */
  die(): void {
    this.exitResolve({ exit_code: 1, signal: null });
    this.handler?.({ type: 'exit', exit_code: 1, signal: null });
  }
}

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

function makeConfig(dir: string): RemoteConfig {
  const files = {
    localRoots: [],
    remoteDeny: [],
    maxFileBytes: 1,
    maxFiles: 1,
    maxTotalBytes: 1,
    maxDepth: 0,
    transferTimeoutMs: 1000,
  };
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
      files,
    },
    security: { hostKeyPolicy: 'pinned' },
    hosts: { web1: { host: '127.0.0.1', user: 'tester' } },
    files,
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

function makeCtx(dir: string, config: RemoteConfig): ToolContext {
  return {
    paths: makePaths(dir),
    log: makeLogger(),
    getConfig: async () => config,
  };
}

async function pinTrust(dir: string): Promise<void> {
  const blob = Buffer.from('session-start-audit-key').toString('base64');
  await writeFile(path.join(dir, 'known_hosts'), `127.0.0.1 ssh-ed25519 ${blob}\n`, 'utf8');
  await writeFile(
    path.join(dir, 'trust.json'),
    JSON.stringify({
      version: 1,
      hosts: {
        web1: {
          algorithm: 'ssh-ed25519',
          keyBlob: blob,
          fingerprint: fingerprintKey(blob),
          firstSeenAt: '2026-01-01T00:00:00.000Z',
          lastVerifiedAt: '2026-01-02T00:00:00.000Z',
        },
      },
    }),
    'utf8',
  );
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

async function readCloseAudits(dir: string): Promise<Array<Record<string, unknown>>> {
  return (await readAudit(dir)).filter((record) => record['tool'] === 'session_close');
}

async function waitForCloseAudits(
  dir: string,
  count: number,
  timeoutMs = 3000,
): Promise<Array<Record<string, unknown>>> {
  const started = Date.now();
  for (;;) {
    const records = await readCloseAudits(dir);
    if (records.length >= count) return records;
    if (Date.now() - started > timeoutMs) {
      throw new Error(`expected ${count} close audit record(s), got ${records.length}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

const tempDirs = new Set<string>();

beforeEach(() => {
  useSessionRegistry(createSessionRegistry());
  bridge.transport = undefined;
  bridge.openCalls = 0;
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

async function setup(): Promise<{ dir: string; ctx: ToolContext }> {
  const dir = await mkdtemp(path.join(tmpdir(), 'remote-mcp-start-audit-'));
  tempDirs.add(dir);
  await pinTrust(dir);
  return { dir, ctx: makeCtx(dir, makeConfig(dir)) };
}

describe('session_start close auditing', () => {
  it('writes exactly one close audit for an explicit session_close', async () => {
    const { dir, ctx } = await setup();
    bridge.transport = new FakeTransport();

    const started = await sessionStart({ host: 'web1' }, ctx);
    expect(started.isError).toBe(false);
    const sessionId = (started.structuredContent as { session_id: string }).session_id;
    expect(bridge.openCalls).toBe(1);

    const closed = await sessionClose({ session_id: sessionId }, ctx);
    expect(closed.isError).toBe(false);

    const audit = await readCloseAudits(dir);
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      tool: 'session_close',
      session_id: sessionId,
      reason: 'explicit',
      outcome: 'ok',
      graceful: true,
    });

    // 会话已从登记簿移除；再次 close 不会产生第二条审计。
    const again = await sessionClose({ session_id: sessionId }, ctx);
    expect(again.isError).toBe(true);
    expect(await readCloseAudits(dir)).toHaveLength(1);
  });

  it('writes one close audit when the remote transport exits on its own', async () => {
    const { dir, ctx } = await setup();
    const transport = new FakeTransport();
    bridge.transport = transport;

    const started = await sessionStart({ host: 'web1' }, ctx);
    expect(started.isError).toBe(false);
    const sessionId = (started.structuredContent as { session_id: string }).session_id;

    transport.die();

    const audit = await waitForCloseAudits(dir, 1);
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      tool: 'session_close',
      session_id: sessionId,
      reason: 'transport_exit',
      outcome: 'error',
    });
  });

  it('skips the audit callback when openSessionTransport fails', async () => {
    const { dir, ctx } = await setup();
    bridge.transport = new FakeTransport();
    // 让 openSessionTransport 返回一个缺少 attach 的对象，触发 createSession 前失败。
    bridge.transport = {};

    const result = await sessionStart({ host: 'web1' }, ctx);
    expect(result.isError).toBe(true);
    expect(await readCloseAudits(dir)).toHaveLength(0);
  });
});
