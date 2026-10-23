import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { RunResult } from '../../../src/types.js';
import type { TransferDeps } from '../../../src/transfer/deps.js';

const execFileAsync = promisify(execFile);

const state = vi.hoisted(() => ({
  executor: null as null | ((command: string) => Promise<Record<string, unknown>>),
  homeCalls: 0,
  home: '/home/u',
}));

vi.mock('../../../src/transfer/deps.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/transfer/deps.js')>();
  return {
    ...actual,
    runRemoteCommand: async (_deps: unknown, command: string) => {
      if (command === 'printf \'%s\' "$HOME"') state.homeCalls += 1;
      if (state.executor === null) throw new Error('no executor configured');
      return state.executor(command);
    },
  };
});

const { probeRemoteManifest, probeRemotePath, resolveRemoteHome } = await import(
  '../../../src/transfer/probe.js'
);

const ABC_SHA = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

async function hasBash(): Promise<boolean> {
  try {
    await execFileAsync('bash', ['--noprofile', '--norc', '-c', 'printf ok']);
    return true;
  } catch {
    return false;
  }
}

const BASH_OK = await hasBash();

function toBashPath(p: string): string {
  if (process.platform !== 'win32') return p;
  return p.replace(/^([A-Za-z]):/, (_, drive: string) => `/${drive.toLowerCase()}`).replace(/\\/g, '/');
}

function runResult(exitCode: number, stdout: string, stderr: string): RunResult {
  return {
    argv: [],
    displayCommand: 'bash',
    exitCode,
    signal: null,
    stdout,
    stderr,
    stdoutBytes: Buffer.byteLength(stdout),
    stderrBytes: Buffer.byteLength(stderr),
    stdoutTruncated: false,
    stderrTruncated: false,
    timedOut: false,
    durationMs: 1,
  };
}

function localExecutor(home: string): (command: string) => Promise<RunResult> {
  return async (command: string): Promise<RunResult> => {
    try {
      const { stdout, stderr } = await execFileAsync('bash', ['--noprofile', '--norc', '-c', command], {
        env: { ...process.env, HOME: toBashPath(home) },
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
        windowsHide: true,
      });
      return runResult(0, stdout, stderr);
    } catch (err) {
      const e = err as { code?: unknown; stdout?: string; stderr?: string };
      return runResult(typeof e.code === 'number' ? e.code : 1, e.stdout ?? '', e.stderr ?? '');
    }
  };
}

function makeDeps(overrides: Partial<TransferDeps> = {}): TransferDeps {
  return {
    target: {
      config: { defaults: { maxOutputBytes: 1048576 } },
      host: { alias: 'web1', cwd: '~', timeouts: { connectMs: 5000, commandMs: 15000, checkMs: 8000 } },
      destination: 'deploy@10.0.0.5:22',
    },
    ctx: {
      paths: { knownHostsFile: 'C:\\cfg\\known_hosts' },
      log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn(), child: vi.fn() },
      getConfig: async () => {
        throw new Error('not used');
      },
    },
    limits: { maxFileBytes: 1000, maxFiles: 100, maxTotalBytes: 10000, maxDepth: 10 },
    deadlineMs: Date.now() + 60_000,
    ...overrides,
  } as unknown as TransferDeps;
}

describe.skipIf(!BASH_OK)('probe (local bash simulation)', () => {
  let base: string;
  let home: string;
  let outside: string;

  beforeEach(async () => {
    base = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-probe-'));
    home = path.join(base, 'home');
    outside = path.join(base, 'outside');
    await fs.mkdir(home);
    await fs.mkdir(outside);
    state.homeCalls = 0;
    state.executor = localExecutor(home);
  });

  afterEach(async () => {
    await fs.rm(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  describe('probeRemotePath', () => {
    it('reports a regular file with size, mode, realpath and hash', async () => {
      await fs.writeFile(path.join(home, 'hello.txt'), 'abc');
      const result = await probeRemotePath(makeDeps(), '~/hello.txt', {
        hash: true,
        realpath: true,
      });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.facts).toMatchObject({
        path: '~/hello.txt',
        exists: true,
        type: 'file',
        size: 3,
        sha256: ABC_SHA,
      });
      expect(result.facts.mode).toBeTypeOf('number');
      expect(result.facts.realpath).toBeTruthy();
      expect(result.facts.realpath!.startsWith('/')).toBe(true);
    });

    it('reports a directory', async () => {
      await fs.mkdir(path.join(home, 'dir'));
      const result = await probeRemotePath(makeDeps(), '~/dir');
      expect(result.ok && result.facts.type).toBe('dir');
    });

    it('detects symlinks before following them', async () => {
      const target = path.join(home, 'target-dir');
      await fs.mkdir(target);
      await fs.symlink(target, path.join(home, 'link'), process.platform === 'win32' ? 'junction' : 'dir');
      const result = await probeRemotePath(makeDeps(), '~/link');
      expect(result.ok && result.facts.type).toBe('symlink');
    });

    it('reports a missing path without an error', async () => {
      const result = await probeRemotePath(makeDeps(), '~/missing');
      expect(result).toEqual({ ok: true, facts: { path: '~/missing', exists: false } });
    });

    it('classifies transport failures', async () => {
      state.executor = async () => runResult(255, '', 'Connection closed by 10.0.0.5');
      const result = await probeRemotePath(makeDeps(), '~/x');
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe('ssh_transport_failure');
    });

    it('classifies malformed output as remote_manifest_failed', async () => {
      state.executor = async () => runResult(0, 'garbage\n', '');
      const result = await probeRemotePath(makeDeps(), '~/x');
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe('remote_manifest_failed');
        expect(result.error.kind).toBe('RemoteExit');
      }
    });
  });

  describe('probeRemoteManifest', () => {
    beforeEach(async () => {
      const tree = path.join(home, 'tree');
      await fs.mkdir(path.join(tree, 'sub'), { recursive: true });
      await fs.writeFile(path.join(tree, 'a.txt'), 'abc');
      await fs.writeFile(path.join(tree, 'sub', 'b.txt'), 'hello');
    });

    it('lists entries with hashes, zeroed directory sizes and sorted paths', async () => {
      const result = await probeRemoteManifest(makeDeps(), '~/tree', { maxFiles: 100, maxDepth: 10 });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entries.map((entry) => entry.path)).toEqual(['a.txt', 'sub', 'sub/b.txt']);
      expect(result.entries[0]).toMatchObject({ type: 'file', size: 3, sha256: ABC_SHA });
      expect(result.entries[1]).toMatchObject({ type: 'dir', size: 0 });
      expect(result.entries[2]!.sha256).toMatch(/^[0-9a-f]{64}$/);
    });

    it('honours maxDepth', async () => {
      const result = await probeRemoteManifest(makeDeps(), '~/tree', { maxDepth: 1 });
      expect(result.ok).toBe(true);
      if (result.ok) expect(result.entries.map((entry) => entry.path)).toEqual(['a.txt', 'sub']);
    });

    it('can skip hashing', async () => {
      const result = await probeRemoteManifest(makeDeps(), '~/tree', { hash: false });
      expect(result.ok).toBe(true);
      if (result.ok) expect(result.entries.every((entry) => entry.sha256 === undefined)).toBe(true);
    });

    it('fails when maxFiles is exceeded', async () => {
      const result = await probeRemoteManifest(makeDeps(), '~/tree', { maxFiles: 2 });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe('too_many_files');
    });

    it('fails when the root is missing', async () => {
      const result = await probeRemoteManifest(makeDeps(), '~/nope');
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.kind).toBe('RemoteExit');
    });
  });

  describe('resolveRemoteHome', () => {
    it('caches per deps and returns the printed home', async () => {
      state.executor = async (command) => {
        if (command === 'printf \'%s\' "$HOME"') return runResult(0, state.home, '');
        return runResult(0, '', '');
      };
      const deps = makeDeps();
      await expect(resolveRemoteHome(deps)).resolves.toBe(state.home);
      await expect(resolveRemoteHome(deps)).resolves.toBe(state.home);
      expect(state.homeCalls).toBe(1);
    });

    it('uses deps.home without running a command', async () => {
      const deps = makeDeps({ home: '/srv/home' });
      await expect(resolveRemoteHome(deps)).resolves.toBe('/srv/home');
      expect(state.homeCalls).toBe(0);
    });
  });
});
