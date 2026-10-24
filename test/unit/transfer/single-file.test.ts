import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { TransferDeps } from '../../../src/transfer/deps.js';
import type { LocalSource } from '../../../src/transfer/local-path.js';

const SHA_HELLO = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';

const state = vi.hoisted(() => {
  const mkRun = (exitCode = 0, stderr = '') => ({
    argv: [],
    displayCommand: 'cmd',
    exitCode,
    signal: null,
    stdout: '',
    stderr,
    stdoutBytes: 0,
    stderrBytes: 0,
    stdoutTruncated: false,
    stderrTruncated: false,
    timedOut: false,
    durationMs: 1,
  });
  return {
    events: [] as string[],
    steps: [] as string[][],
    mkRun,
    probe: ((_target: string) => ({ ok: true, facts: {} })) as (target: string) => unknown,
    verifyRemote: (() => undefined) as () => unknown,
    verifyLocal: (() => undefined) as () => unknown,
    swap: (() => ({
      ok: true,
      backup: '/home/u/.remote-mcp-tmp-0123456789abcdef',
      run: mkRun(0),
      rolledBack: false,
    })) as () => unknown,
    sftpRun: () => mkRun(0),
    downloadContent: undefined as Buffer | undefined,
  };
});

vi.mock('../../../src/transfer/probe.js', () => ({
  probeRemotePath: async (_deps: unknown, target: string) => {
    state.events.push(target === '/home/u' ? 'probe-parent' : 'probe');
    return state.probe(target);
  },
  resolveRemoteHome: async () => '/home/u',
}));

vi.mock('../../../src/transfer/verify.js', () => ({
  verifyRemoteFile: async () => {
    state.events.push('verify-remote');
    return state.verifyRemote();
  },
  verifyLocalFile: async () => {
    state.events.push('verify-local');
    return state.verifyLocal();
  },
}));

vi.mock('../../../src/transfer/stage.js', () => ({
  assertRemoteTempPath: () => undefined,
  newRemoteTempPath: (target: string) => {
    const idx = target.lastIndexOf('/');
    return `${target.slice(0, idx)}/.remote-mcp-tmp-0123456789abcdef`;
  },
  swapRemoteIntoPlace: async () => {
    state.events.push('swap');
    return state.swap();
  },
  removeRemoteTree: async () => {
    state.events.push('cleanup-remote');
    return { ok: true, run: state.mkRun(0) };
  },
}));

vi.mock('../../../src/transfer/sftp.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/transfer/sftp.js')>();
  const { promises: fsPromises } = await import('node:fs');
  return {
    ...actual,
    runSftpBatch: async (_deps: unknown, steps: readonly string[]) => {
      state.steps.push([...steps]);
      const first = steps[0] ?? '';
      if (first.startsWith('get ')) {
        state.events.push('get');
        const match = /^get "(?:[^"\\]|\\.)*" "(.*)"$/.exec(first);
        if (match !== null && state.downloadContent !== undefined) {
          await fsPromises.writeFile(match[1]!, state.downloadContent);
        }
      } else {
        state.events.push('put');
      }
      return state.sftpRun();
    },
  };
});

const { uploadSingleFile, downloadSingleFile } = await import(
  '../../../src/transfer/single-file.js'
);

function makeDeps(home = '/home/u'): TransferDeps {
  return {
    target: {
      config: { defaults: { maxOutputBytes: 1048576 } },
      host: {
        alias: 'web1',
        host: '10.0.0.5',
        user: 'deploy',
        port: 22,
        cwd: '~',
        timeouts: { connectMs: 5000, commandMs: 15000, checkMs: 8000 },
        maxOutputBytes: 1048576,
        sudo: { mode: 'off', allow: [], deny: [] },
      },
      destination: 'deploy@10.0.0.5:22',
    },
    knownHostsFile: 'C:\\cfg\\known_hosts',
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn(), child: vi.fn() },
    limits: { maxFileBytes: 1_000_000, maxFiles: 100, maxTotalBytes: 10_000_000, maxDepth: 10 },
    deadlineMs: Date.now() + 60_000,
    home,
  } as unknown as TransferDeps;
}

function probeFacts(overrides: Record<string, unknown> = {}) {
  return {
    ok: true,
    facts: {
      path: '/home/u/a.txt',
      exists: true,
      type: 'file',
      size: 5,
      mode: 0o644,
      realpath: '/home/u/a.txt',
      sha256: SHA_HELLO,
      ...overrides,
    },
  };
}

function localSource(file: string, mode = 0o644): LocalSource {
  return {
    path: file,
    realPath: file,
    kind: 'file',
    size: 5,
    mode,
    stat: {} as LocalSource['stat'],
  };
}

function parentDirFacts(overrides: Record<string, unknown> = {}) {
  return {
    ok: true,
    facts: {
      path: '/home/u',
      exists: true,
      type: 'dir',
      size: 0,
      mode: 0o755,
      realpath: '/home/u',
      ...overrides,
    },
  };
}

function reset(): void {
  state.events.length = 0;
  state.steps.length = 0;
  state.probe = (target: string) =>
    target === '/home/u'
      ? parentDirFacts()
      : probeFacts({ exists: false, type: undefined, size: undefined });
  state.verifyRemote = () => undefined;
  state.verifyLocal = () => undefined;
  state.swap = () => ({
    ok: true,
    backup: '/home/u/.remote-mcp-tmp-0123456789abcdef',
    run: state.mkRun(0),
    rolledBack: false,
  });
  state.sftpRun = () => state.mkRun(0);
  state.downloadContent = undefined;
}

describe('single-file transfer state machines', () => {
  let dir: string;
  let localFile: string;
  let target: string;

  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-single-'));
    localFile = path.join(dir, 'local.txt');
    await fs.writeFile(localFile, 'hello');
    target = path.join(dir, 'downloaded.txt');
    reset();
  });

  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  describe('uploadSingleFile', () => {
    it('probes, puts, verifies and swaps in order, then reports facts', async () => {
      const facts = await uploadSingleFile({
        deps: makeDeps(),
        local: localSource(localFile, 0o640),
        remote: '~/a.txt',
        overwrite: false,
      });

      expect(facts.ok).toBe(true);
      expect(facts.failure).toBeUndefined();
      expect(facts.direction).toBe('upload');
      expect(facts.kind).toBe('file');
      expect(facts.files).toBe(1);
      expect(facts.bytes).toBe(5);
      expect(facts.sha256).toBe(SHA_HELLO);
      expect(facts.verified).toBe(true);
      expect(facts.atomicReplace).toBe(true);
      expect(facts.overwritten).toBe(false);
      expect(state.events.slice(0, 5)).toEqual([
        'probe',
        'probe-parent',
        'put',
        'verify-remote',
        'swap',
      ]);
      // 同目录远端临时文件：put + chmod 一次 batch。
      expect(state.steps[0]).toHaveLength(2);
      expect(state.steps[0]![0]).toContain('put ');
      expect(state.steps[0]![0]).toContain('/.remote-mcp-tmp-0123456789abcdef');
      expect(state.steps[0]![1]).toContain('chmod 640');
    });

    it('refuses an existing target when overwrite is false without spawning sftp', async () => {
      state.probe = () => probeFacts();
      const facts = await uploadSingleFile({
        deps: makeDeps(),
        local: localSource(localFile),
        remote: '~/a.txt',
        overwrite: false,
      });
      expect(facts.ok).toBe(false);
      expect(facts.failure?.code).toBe('target_exists');
      expect(state.events).toEqual(['probe']);
      expect(state.steps).toHaveLength(0);
    });

    it('replaces an existing target when overwrite is true and cleans the backup', async () => {
      state.probe = () => probeFacts();
      const facts = await uploadSingleFile({
        deps: makeDeps(),
        local: localSource(localFile),
        remote: '~/a.txt',
        overwrite: true,
      });
      expect(facts.ok).toBe(true);
      expect(facts.overwritten).toBe(true);
      expect(state.events).toContain('swap');
      expect(state.events).toContain('cleanup-remote');
    });

    it('rejects symlinks and directories', async () => {
      state.probe = () => probeFacts({ type: 'symlink' });
      const link = await uploadSingleFile({
        deps: makeDeps(),
        local: localSource(localFile),
        remote: '~/a.txt',
        overwrite: false,
      });
      expect(link.failure?.code).toBe('remote_symlink');

      state.events.length = 0;
      state.probe = () => probeFacts({ type: 'dir' });
      const directory = await uploadSingleFile({
        deps: makeDeps(),
        local: localSource(localFile),
        remote: '~/a.txt',
        overwrite: false,
      });
      expect(directory.failure?.code).toBe('remote_invalid_type');
      expect(state.events).toEqual(['probe']);
    });

    it('does not swap when remote verification fails', async () => {
      state.verifyRemote = () => ({
        kind: 'RemoteExit',
        code: 'verify_sha256_mismatch',
        message: 'mismatch',
        retryable: false,
      });
      const facts = await uploadSingleFile({
        deps: makeDeps(),
        local: localSource(localFile),
        remote: '~/a.txt',
        overwrite: false,
      });
      expect(facts.ok).toBe(false);
      expect(facts.failure?.code).toBe('verify_sha256_mismatch');
      expect(state.events).not.toContain('swap');
    });

    it('reports sftp failures with diagnostics', async () => {
      state.sftpRun = () => state.mkRun(1, 'remote open("/home/u/x"): Permission denied\nFailure');
      const facts = await uploadSingleFile({
        deps: makeDeps(),
        local: localSource(localFile),
        remote: '~/a.txt',
        overwrite: false,
      });
      expect(facts.ok).toBe(false);
      expect(facts.failure?.code).toBe('remote_exit');
      expect(facts.failure?.details?.['diagnostics']).toEqual(
        expect.arrayContaining(['permission denied on the remote path']),
      );
      expect(facts.run?.exitCode).toBe(1);
    });

    it('rejects a write whose parent realpath is denied (symlink write-through)', async () => {
      state.probe = (target: string) =>
        target === '/home/u'
          ? parentDirFacts({ realpath: '/etc' })
          : probeFacts({ exists: false, type: undefined, size: undefined });
      const facts = await uploadSingleFile({
        deps: makeDeps(),
        local: localSource(localFile),
        remote: '~/new.txt',
        overwrite: false,
      });
      expect(facts.ok).toBe(false);
      expect(facts.failure).toMatchObject({ kind: 'Policy', code: 'remote_denied_write' });
      expect(state.steps).toHaveLength(0);
      expect(state.events).toEqual(['probe', 'probe-parent']);
    });

    it('rejects a missing parent directory', async () => {
      state.probe = (target: string) =>
        target === '/home/u'
          ? { ok: true, facts: { path: target, exists: false } }
          : probeFacts({ exists: false, type: undefined, size: undefined });
      const facts = await uploadSingleFile({
        deps: makeDeps(),
        local: localSource(localFile),
        remote: '~/new.txt',
        overwrite: false,
      });
      expect(facts.failure).toMatchObject({ kind: 'Policy', code: 'target_parent_missing' });
      expect(state.steps).toHaveLength(0);
    });

    it('rejects a parent that is not a directory', async () => {
      state.probe = (target: string) =>
        target === '/home/u'
          ? parentDirFacts({ type: 'symlink' })
          : probeFacts({ exists: false, type: undefined, size: undefined });
      const facts = await uploadSingleFile({
        deps: makeDeps(),
        local: localSource(localFile),
        remote: '~/new.txt',
        overwrite: false,
      });
      expect(facts.failure).toMatchObject({
        kind: 'Policy',
        code: 'target_parent_not_directory',
      });
      expect(state.steps).toHaveLength(0);
    });
  });

  describe('downloadSingleFile', () => {
    const localTarget = (): { path: string; exists: boolean } => ({
      path: target,
      exists: false,
    });

    it('gets, verifies, closes the temp handle and renames into place', async () => {
      state.probe = () => probeFacts();
      state.downloadContent = Buffer.from('hello');
      const openSpy = vi.spyOn(fs, 'open');
      try {
        const facts = await downloadSingleFile({
          deps: makeDeps(),
          remote: '~/a.txt',
          localTarget: localTarget(),
          overwrite: false,
        });
        expect(facts.ok).toBe(true);
        expect(facts.sha256).toBe(SHA_HELLO);
        expect(facts.bytes).toBe(5);
        expect(state.events.slice(0, 3)).toEqual(['probe', 'get', 'verify-local']);
        expect(await fs.readFile(target, 'utf8')).toBe('hello');
        const handle = (await openSpy.mock.results[0]!.value) as { fd: number };
        expect(handle.fd).toBe(-1);
      } finally {
        openSpy.mockRestore();
      }
      // 改名成功后 cleanup 不得再删除临时文件，也不留下任何临时项。
      const leftovers = (await fs.readdir(dir)).filter((name) =>
        name.startsWith('.remote-mcp-'),
      );
      expect(leftovers).toEqual([]);
    });

    it('refuses an existing local target when overwrite is false', async () => {
      await fs.writeFile(target, 'old');
      state.probe = () => probeFacts();
      const facts = await downloadSingleFile({
        deps: makeDeps(),
        remote: '~/a.txt',
        localTarget: { path: target, exists: true },
        overwrite: false,
      });
      expect(facts.ok).toBe(false);
      expect(facts.failure?.code).toBe('target_exists');
      expect(state.events).toEqual(['probe']);
      expect(await fs.readFile(target, 'utf8')).toBe('old');
    });

    it('backs up and replaces an existing local target when overwrite is true', async () => {
      await fs.writeFile(target, 'old');
      state.probe = () => probeFacts();
      state.downloadContent = Buffer.from('hello');
      const facts = await downloadSingleFile({
        deps: makeDeps(),
        remote: '~/a.txt',
        localTarget: { path: target, exists: true },
        overwrite: true,
      });
      expect(facts.ok).toBe(true);
      expect(facts.overwritten).toBe(true);
      expect(await fs.readFile(target, 'utf8')).toBe('hello');
      const leftovers = (await fs.readdir(dir)).filter((name) =>
        name.startsWith('.remote-mcp-'),
      );
      expect(leftovers).toEqual([]);
    });

    it('rejects a target that appears while verification is running', async () => {
      state.probe = () => probeFacts();
      state.downloadContent = Buffer.from('hello');
      state.verifyLocal = async () => {
        await fs.writeFile(target, 'racer');
        return undefined;
      };
      const facts = await downloadSingleFile({
        deps: makeDeps(),
        remote: '~/a.txt',
        localTarget: { path: target, exists: false },
        overwrite: false,
      });
      expect(facts.failure?.code).toBe('target_exists');
      expect(await fs.readFile(target, 'utf8')).toBe('racer');
    });

    it('rejects remote symlinks, directories and missing sources', async () => {
      state.probe = () => probeFacts({ type: 'symlink' });
      expect(
        (await downloadSingleFile({
          deps: makeDeps(),
          remote: '~/a.txt',
          localTarget: localTarget(),
          overwrite: false,
        })).failure?.code,
      ).toBe('remote_symlink');

      state.probe = () => probeFacts({ type: 'dir' });
      expect(
        (await downloadSingleFile({
          deps: makeDeps(),
          remote: '~/a.txt',
          localTarget: localTarget(),
          overwrite: false,
        })).failure?.code,
      ).toBe('remote_invalid_type');

      state.probe = () => ({ ok: true, facts: { path: '/home/u/a.txt', exists: false } });
      expect(
        (await downloadSingleFile({
          deps: makeDeps(),
          remote: '~/a.txt',
          localTarget: localTarget(),
          overwrite: false,
        })).failure?.code,
      ).toBe('remote_source_not_found');
    });

    it('closes the temp handle and removes the temporary file when verification fails', async () => {
      state.probe = () => probeFacts();
      state.downloadContent = Buffer.from('hello');
      state.verifyLocal = () => ({
        kind: 'RemoteExit',
        code: 'verify_sha256_mismatch',
        message: 'mismatch',
        retryable: false,
      });
      const openSpy = vi.spyOn(fs, 'open');
      try {
        const facts = await downloadSingleFile({
          deps: makeDeps(),
          remote: '~/a.txt',
          localTarget: localTarget(),
          overwrite: false,
        });
        expect(facts.ok).toBe(false);
        const handle = (await openSpy.mock.results[0]!.value) as { fd: number };
        expect(handle.fd).toBe(-1);
      } finally {
        openSpy.mockRestore();
      }
      expect(await fs.readdir(dir)).toEqual(['local.txt']);
    });

    it('fails when the remote hash is unavailable', async () => {
      state.probe = () => probeFacts({ sha256: undefined });
      const facts = await downloadSingleFile({
        deps: makeDeps(),
        remote: '~/a.txt',
        localTarget: localTarget(),
        overwrite: false,
      });
      expect(facts.failure?.code).toBe('remote_hash_unavailable');
    });
  });
});
