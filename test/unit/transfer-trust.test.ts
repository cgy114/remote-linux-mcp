import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { fingerprintKey } from '../../src/util/fingerprint.js';
import type { ToolContext } from '../../src/tools/common.js';
import type { RemoteConfig } from '../../src/types.js';

const state = vi.hoisted(() => ({
  runs: 0,
  sftpRuns: 0,
}));

vi.mock('../../src/ssh/runner.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/ssh/runner.js')>();
  const mkRun = () => ({
    argv: [],
    displayCommand: 'cmd',
    exitCode: 0,
    signal: null,
    stdout: '',
    stderr: '',
    stdoutBytes: 0,
    stderrBytes: 0,
    stdoutTruncated: false,
    stderrTruncated: false,
    timedOut: false,
    durationMs: 1,
  });
  return {
    ...actual,
    runSsh: async () => {
      state.runs += 1;
      return mkRun();
    },
    runSftp: async () => {
      state.sftpRuns += 1;
      return mkRun();
    },
  };
});

const { sshUpload } = await import('../../src/tools/ssh-upload.js');
const { sshReadFile } = await import('../../src/tools/ssh-read-file.js');
const { sshWriteFile } = await import('../../src/tools/ssh-write-file.js');

let base: string;
let localRoot: string;
let config: RemoteConfig;
let keyBlob: string;
let fingerprint: string;

const KEY = Buffer.from('remote-mcp-unit-test-ed25519-blob').toString('base64');

function makeConfig(): RemoteConfig {
  const files = {
    localRoots: [localRoot],
    remoteDeny: [],
    maxFileBytes: 1024 * 1024,
    maxFiles: 100,
    maxTotalBytes: 10 * 1024 * 1024,
    maxDepth: 10,
    transferTimeoutMs: 30_000,
  };
  return {
    version: 1,
    sourcePath: path.join(base, 'config.yaml'),
    baseDir: base,
    defaults: {
      port: 22,
      defaultCwd: '~',
      timeouts: { connectMs: 5000, commandMs: 15000, checkMs: 8000 },
      maxOutputBytes: 1048576,
      sudo: { mode: 'off', allow: [], deny: [] },
      files,
    },
    security: { hostKeyPolicy: 'pinned' },
    hosts: { web1: { host: '127.0.0.1', user: 'u' } },
    files,
  };
}

async function makeCtx(trusted: boolean): Promise<ToolContext> {
  const configDir = await fs.mkdtemp(path.join(base, trusted ? 'trusted-' : 'untrusted-'));
  if (trusted) {
    await fs.writeFile(path.join(configDir, 'known_hosts'), `127.0.0.1 ssh-ed25519 ${KEY}\n`);
    await fs.writeFile(
      path.join(configDir, 'trusted.json'),
      JSON.stringify({
        version: 1,
        hosts: {
          web1: {
            algorithm: 'ssh-ed25519',
            keyBlob: KEY,
            fingerprint,
            firstSeenAt: '2026-01-01T00:00:00.000Z',
            lastVerifiedAt: '2026-01-01T00:00:00.000Z',
          },
        },
      }),
    );
  }
  return {
    paths: {
      configFile: path.join(configDir, 'config.yaml'),
      configDir,
      knownHostsFile: path.join(configDir, 'known_hosts'),
      trustRegistryFile: path.join(configDir, 'trusted.json'),
      trustLockFile: path.join(configDir, '.trust.lock'),
      source: 'flag',
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn(), child: vi.fn() },
    getConfig: async () => config,
  };
}

async function auditRecords(ctx: ToolContext): Promise<Record<string, unknown>[]> {
  const text = await fs.readFile(path.join(ctx.paths.configDir, 'audit.jsonl'), 'utf8');
  return text
    .split(/\r?\n/)
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

beforeAll(async () => {
  base = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-trust-'));
  localRoot = path.join(base, 'root');
  await fs.mkdir(localRoot);
  await fs.writeFile(path.join(localRoot, 'a.txt'), 'hello');
  config = makeConfig();
  keyBlob = KEY;
  fingerprint = fingerprintKey(keyBlob);
});

afterAll(async () => {
  await fs.rm(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
});

describe('trust and prepare denials never spawn', () => {
  it('denies an untrusted host before any ssh/sftp process and audits it', async () => {
    state.runs = 0;
    state.sftpRuns = 0;
    const ctx = await makeCtx(false);

    const result = await sshUpload(
      {
        host: 'web1',
        local_path: path.join(localRoot, 'a.txt'),
        remote_path: '~/a.txt',
      },
      ctx,
    );

    expect(result.isError).toBe(true);
    expect(state.runs).toBe(0);
    expect(state.sftpRuns).toBe(0);
    const records = await auditRecords(ctx);
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      tool: 'ssh_upload',
      outcome: 'denied',
      queue_ms: 0,
    });
  });

  it('denies a local path outside local_roots after trust passes', async () => {
    state.runs = 0;
    state.sftpRuns = 0;
    const ctx = await makeCtx(true);
    const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-outside-'));
    const outsideFile = path.join(outside, 'secret.txt');
    await fs.writeFile(outsideFile, 'nope');

    try {
      const result = await sshUpload(
        { host: 'web1', local_path: outsideFile, remote_path: '~/a.txt' },
        ctx,
      );
      expect(result.isError).toBe(true);
      expect(result.structuredContent).toMatchObject({
        error: { code: 'local_root_not_allowed' },
      });
      expect(state.runs).toBe(0);
      expect(state.sftpRuns).toBe(0);
      const records = await auditRecords(ctx);
      expect(records[0]).toMatchObject({ outcome: 'denied', failureCode: 'local_root_not_allowed' });
    } finally {
      await fs.rm(outside, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });

  it('denies reading ~/.ssh before spawn and audits without content', async () => {
    state.runs = 0;
    const ctx = await makeCtx(true);
    const result = await sshReadFile({ host: 'web1', path: '~/.ssh/id_ed25519' }, ctx);
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({ error: { code: 'remote_denied_read' } });
    expect(state.runs).toBe(0);
    const records = await auditRecords(ctx);
    expect(records[0]).toMatchObject({ tool: 'ssh_read_file', outcome: 'denied' });
  });

  it('denies writes to builtin write-deny paths before spawn', async () => {
    state.runs = 0;
    state.sftpRuns = 0;
    const ctx = await makeCtx(true);
    const marker = 'NEVER_LOGGED_CONTENT';
    const result = await sshWriteFile(
      { host: 'web1', path: '/etc/passwd', content: marker },
      ctx,
    );
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({ error: { code: 'remote_denied_write' } });
    expect(state.runs).toBe(0);
    expect(state.sftpRuns).toBe(0);
    const raw = await fs.readFile(path.join(ctx.paths.configDir, 'audit.jsonl'), 'utf8');
    expect(raw).not.toContain(marker);
  });
});
