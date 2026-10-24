import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { TransferDeps } from '../../../src/transfer/deps.js';
import type { LocalSource } from '../../../src/transfer/local-path.js';
import type { ManifestEntry } from '../../../src/transfer/manifest.js';

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
    mkRun,
    probePath: ((_target: string) => ({ ok: true, facts: {} })) as (target: string) => unknown,
    probeManifest: (() => ({ ok: true, entries: [] })) as () => unknown,
    swap: (() => ({ ok: true, backup: '/tmp/.backup', run: mkRun(0), rolledBack: false })) as () => unknown,
    remoteRun: (() => mkRun(0)) as () => unknown,
    remoteTarRun: (() => mkRun(0)) as () => unknown,
    extractFiles: {} as Record<string, { content: Buffer; mode?: number }>,
    archiveMaxOutputBytes: undefined as number | undefined,
    remoteTarCalls: [] as { command: string; maxOutputBytes?: number }[],
  };
});

vi.mock('../../../src/transfer/probe.js', () => ({
  probeRemotePath: async (_deps: unknown, target: string) => {
    state.events.push(target === '/home/u' ? 'probe-parent' : 'probe');
    return state.probePath(target);
  },
  probeRemoteManifest: async () => {
    state.events.push('manifest');
    return state.probeManifest();
  },
  resolveRemoteHome: async () => '/home/u',
}));

vi.mock('../../../src/transfer/deps.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/transfer/deps.js')>();
  return {
    ...actual,
    runRemoteCommand: async () => {
      state.events.push('mkdir');
      return state.remoteRun();
    },
  };
});

vi.mock('../../../src/transfer/stage.js', () => ({
  assertRemoteTempPath: () => undefined,
  newRemoteTempPath: (target: string) =>
    `${target.slice(0, target.lastIndexOf('/'))}/.remote-mcp-tmp-0123456789abcdef`,
  swapRemoteIntoPlace: async () => {
    state.events.push('swap');
    return state.swap();
  },
  removeRemoteTree: async () => {
    state.events.push('cleanup-remote');
    return { ok: true, run: state.mkRun(0) };
  },
}));

vi.mock('../../../src/transfer/tar.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/transfer/tar.js')>();
  const { promises: fsPromises } = await import('node:fs');
  return {
    ...actual,
    createLocalArchive: async (opts: { maxOutputBytes?: number }) => {
      state.events.push('archive');
      state.archiveMaxOutputBytes = opts.maxOutputBytes;
      return state.remoteTarRun();
    },
    runLocalTar: async (opts: { argv: readonly string[] }) => {
      state.events.push('extract-local');
      const destDir = opts.argv[1]!;
      for (const [rel, file] of Object.entries(state.extractFiles)) {
        const target = path.join(destDir, ...rel.split('/'));
        await fsPromises.mkdir(path.dirname(target), { recursive: true });
        await fsPromises.writeFile(target, file.content, {
          ...(file.mode !== undefined ? { mode: file.mode } : {}),
        });
        if (file.mode !== undefined && process.platform !== 'win32') {
          await fsPromises.chmod(target, file.mode);
        }
      }
      return state.remoteTarRun();
    },
    runRemoteTar: async (
      _deps: unknown,
      command: string,
      opts: { maxOutputBytes?: number } = {},
    ) => {
      state.events.push(command.includes('-xpf') ? 'extract' : 'create');
      state.remoteTarCalls.push({
        command,
        ...(opts.maxOutputBytes !== undefined ? { maxOutputBytes: opts.maxOutputBytes } : {}),
      });
      return state.remoteTarRun();
    },
  };
});

const { uploadTree, downloadTree } = await import('../../../src/transfer/directory.js');

function makeDeps(): TransferDeps {
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
    home: '/home/u',
  } as unknown as TransferDeps;
}

const HELLO_ENTRY: ManifestEntry = {
  path: 'a.txt',
  type: 'file',
  size: 5,
  mode: 0o644,
  sha256: SHA_HELLO,
};

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
  state.probePath = (target: string) =>
    target === '/home/u'
      ? parentDirFacts()
      : { ok: true, facts: { path: target, exists: false } };
  state.probeManifest = () => ({ ok: true, entries: [] });
  state.swap = () => ({
    ok: true,
    backup: '/home/u/.remote-mcp-tmp-0123456789abcdef',
    run: state.mkRun(0),
    rolledBack: false,
  });
  state.remoteRun = () => state.mkRun(0);
  state.remoteTarRun = () => state.mkRun(0);
  state.extractFiles = {};
  state.archiveMaxOutputBytes = undefined;
  state.remoteTarCalls.length = 0;
}

/** makeDeps().limits 对应的归档流上限（10 MB 总量 + 100 项 + 64 MiB）。 */
const EXPECTED_ARCHIVE_LIMIT = 10_000_000 + 100 * 1024 + 64 * 1024 * 1024;

describe('directory transfer state machines', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-dir-'));
    reset();
  });

  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  describe('uploadTree', () => {
    function source(): LocalSource {
      return {
        path: dir,
        realPath: dir,
        kind: 'dir',
        size: 0,
        mode: 0o755,
        stat: {} as LocalSource['stat'],
      };
    }

    it('stages, archives, extracts, verifies the manifest and swaps', async () => {
      state.probeManifest = () => ({ ok: true, entries: [HELLO_ENTRY] });
      const facts = await uploadTree({
        deps: makeDeps(),
        local: source(),
        manifest: [HELLO_ENTRY],
        remote: '~/tree',
        overwrite: false,
      });

      expect(facts.ok).toBe(true);
      expect(facts.kind).toBe('directory');
      expect(facts.files).toBe(1);
      expect(facts.bytes).toBe(5);
      expect(facts.verified).toBe(true);
      expect(facts.manifestDigest).toMatch(/^[0-9a-f]{64}$/);
      expect(state.events.slice(0, 7)).toEqual([
        'probe',
        'probe-parent',
        'mkdir',
        'archive',
        'extract',
        'manifest',
        'swap',
      ]);
    });

    it('archives with the archive stream limit instead of the 1 MiB output default', async () => {
      state.probeManifest = () => ({ ok: true, entries: [HELLO_ENTRY] });
      const facts = await uploadTree({
        deps: makeDeps(),
        local: source(),
        manifest: [HELLO_ENTRY],
        remote: '~/tree',
        overwrite: false,
      });

      expect(facts.ok).toBe(true);
      expect(state.archiveMaxOutputBytes).toBe(EXPECTED_ARCHIVE_LIMIT);
      expect(state.archiveMaxOutputBytes).not.toBe(1_048_576);
    });

    it('refuses an existing target when overwrite is false', async () => {
      state.probePath = () => ({
        ok: true,
        facts: { path: '/home/u/tree', exists: true, type: 'dir', realpath: '/home/u/tree' },
      });
      const facts = await uploadTree({
        deps: makeDeps(),
        local: source(),
        manifest: [HELLO_ENTRY],
        remote: '~/tree',
        overwrite: false,
      });
      expect(facts.failure?.code).toBe('target_exists');
      expect(state.events).toEqual(['probe']);
    });

    it('rejects symlink targets', async () => {
      state.probePath = () => ({
        ok: true,
        facts: { path: '/home/u/tree', exists: true, type: 'symlink' },
      });
      const facts = await uploadTree({
        deps: makeDeps(),
        local: source(),
        manifest: [HELLO_ENTRY],
        remote: '~/tree',
        overwrite: true,
      });
      expect(facts.failure?.code).toBe('remote_symlink');
    });

    it.skipIf(process.platform !== 'win32')(
      'ignores directory-mode differences produced by Windows archives',
      async () => {
        const expectedDir: ManifestEntry = { path: 'sub', type: 'dir', size: 0, mode: 0o666 };
        const stagedDir: ManifestEntry = { path: 'sub', type: 'dir', size: 0, mode: 0o777 };
        state.probeManifest = () => ({ ok: true, entries: [stagedDir, HELLO_ENTRY] });
        const facts = await uploadTree({
          deps: makeDeps(),
          local: source(),
          manifest: [expectedDir, HELLO_ENTRY],
          remote: '~/tree',
          overwrite: false,
        });
        expect(facts.ok).toBe(true);
        expect(facts.verified).toBe(true);
      },
    );

    it('does not swap when the staged manifest differs', async () => {
      state.probeManifest = () => ({
        ok: true,
        entries: [{ ...HELLO_ENTRY, sha256: '0'.repeat(64) }],
      });
      const facts = await uploadTree({
        deps: makeDeps(),
        local: source(),
        manifest: [HELLO_ENTRY],
        remote: '~/tree',
        overwrite: false,
      });
      expect(facts.failure?.code).toBe('verify_manifest_mismatch');
      expect(state.events).not.toContain('swap');
      expect(state.events).toContain('cleanup-remote');
    });

    it('fails before archiving when staging mkdir fails', async () => {
      state.remoteRun = () => state.mkRun(1, 'mkdir: cannot create directory');
      const facts = await uploadTree({
        deps: makeDeps(),
        local: source(),
        manifest: [HELLO_ENTRY],
        remote: '~/tree',
        overwrite: false,
      });
      expect(facts.ok).toBe(false);
      expect(facts.failure?.code).toBe('remote_exit');
      expect(state.events).not.toContain('archive');
    });

    it('rejects a parent realpath denied for writes', async () => {
      state.probePath = (target: string) =>
        target === '/home/u'
          ? parentDirFacts({ realpath: '/etc' })
          : { ok: true, facts: { path: target, exists: false } };
      const facts = await uploadTree({
        deps: makeDeps(),
        local: source(),
        manifest: [HELLO_ENTRY],
        remote: '~/new-tree',
        overwrite: false,
      });
      expect(facts.failure).toMatchObject({ kind: 'Policy', code: 'remote_denied_write' });
      expect(state.events).toEqual(['probe', 'probe-parent']);
      expect(state.events).not.toContain('mkdir');
    });

    it('rejects a missing or non-directory parent', async () => {
      state.probePath = (target: string) =>
        target === '/home/u'
          ? { ok: true, facts: { path: target, exists: false } }
          : { ok: true, facts: { path: target, exists: false } };
      const missing = await uploadTree({
        deps: makeDeps(),
        local: source(),
        manifest: [HELLO_ENTRY],
        remote: '~/new-tree',
        overwrite: false,
      });
      expect(missing.failure?.code).toBe('target_parent_missing');

      state.events.length = 0;
      state.probePath = (target: string) =>
        target === '/home/u'
          ? parentDirFacts({ type: 'file' })
          : { ok: true, facts: { path: target, exists: false } };
      const notDir = await uploadTree({
        deps: makeDeps(),
        local: source(),
        manifest: [HELLO_ENTRY],
        remote: '~/new-tree',
        overwrite: false,
      });
      expect(notDir.failure?.code).toBe('target_parent_not_directory');
      expect(state.events).toEqual(['probe', 'probe-parent']);
    });
  });

  describe('downloadTree', () => {
    const target = (): { path: string; exists: boolean } => ({
      path: path.join(dir, 'out'),
      exists: false,
    });

    function remoteDir(): void {
      state.probePath = () => ({
        ok: true,
        facts: { path: '/home/u/tree', exists: true, type: 'dir', realpath: '/home/u/tree' },
      });
    }

    it('archives, extracts, verifies the local manifest and renames into place', async () => {
      remoteDir();
      state.probeManifest = () => ({ ok: true, entries: [HELLO_ENTRY] });
      state.extractFiles = { 'a.txt': { content: Buffer.from('hello'), mode: 0o644 } };

      const facts = await downloadTree({
        deps: makeDeps(),
        remote: '~/tree',
        localTarget: target(),
        overwrite: false,
      });

      expect(facts.ok).toBe(true);
      expect(facts.files).toBe(1);
      expect(facts.bytes).toBe(5);
      expect(facts.verified).toBe(true);
      expect(await fs.readFile(path.join(dir, 'out', 'a.txt'), 'utf8')).toBe('hello');
      expect(state.events.slice(0, 4)).toEqual(['probe', 'manifest', 'create', 'extract-local']);
    });

    it('creates the remote archive with the archive stream limit', async () => {
      remoteDir();
      state.probeManifest = () => ({ ok: true, entries: [HELLO_ENTRY] });
      state.extractFiles = { 'a.txt': { content: Buffer.from('hello'), mode: 0o644 } };

      const facts = await downloadTree({
        deps: makeDeps(),
        remote: '~/tree',
        localTarget: target(),
        overwrite: false,
      });

      expect(facts.ok).toBe(true);
      const create = state.remoteTarCalls.find((call) => call.command.includes(' -cf - '));
      expect(create).toBeDefined();
      expect(create?.maxOutputBytes).toBe(EXPECTED_ARCHIVE_LIMIT);
      expect(create?.maxOutputBytes).not.toBe(1_048_576);
    });

    it('rejects a non-directory remote source', async () => {
      state.probePath = () => ({
        ok: true,
        facts: { path: '/home/u/tree', exists: true, type: 'file' },
      });
      const facts = await downloadTree({
        deps: makeDeps(),
        remote: '~/tree',
        localTarget: target(),
        overwrite: false,
      });
      expect(facts.failure?.code).toBe('remote_invalid_type');
      expect(state.events).toEqual(['probe']);
    });

    it('enforces file size limits from the remote manifest', async () => {
      remoteDir();
      state.probeManifest = () => ({
        ok: true,
        entries: [{ ...HELLO_ENTRY, size: 2_000_000 }],
      });
      const facts = await downloadTree({
        deps: makeDeps(),
        remote: '~/tree',
        localTarget: target(),
        overwrite: false,
      });
      expect(facts.failure?.code).toBe('file_too_large');
    });

    it('does not touch an existing target when overwrite is false', async () => {
      remoteDir();
      state.probeManifest = () => ({ ok: true, entries: [HELLO_ENTRY] });
      const out = path.join(dir, 'out');
      await fs.mkdir(out);
      await fs.writeFile(path.join(out, 'old.txt'), 'old');

      const facts = await downloadTree({
        deps: makeDeps(),
        remote: '~/tree',
        localTarget: { path: out, exists: true },
        overwrite: false,
      });
      expect(facts.failure?.code).toBe('target_exists');
      expect(await fs.readFile(path.join(out, 'old.txt'), 'utf8')).toBe('old');
    });

    it('refuses to replace a regular file with a directory when overwrite is true', async () => {
      remoteDir();
      state.probeManifest = () => ({ ok: true, entries: [HELLO_ENTRY] });
      const out = path.join(dir, 'out');
      await fs.writeFile(out, 'file-content');

      const facts = await downloadTree({
        deps: makeDeps(),
        remote: '~/tree',
        localTarget: { path: out, exists: true },
        overwrite: true,
      });
      expect(facts.failure).toMatchObject({ kind: 'Policy', code: 'target_type_mismatch' });
      expect(await fs.readFile(out, 'utf8')).toBe('file-content');
      expect(state.events).toEqual(['probe', 'manifest']);
    });

    it('reports target_exists for a file target when overwrite is false', async () => {
      remoteDir();
      state.probeManifest = () => ({ ok: true, entries: [HELLO_ENTRY] });
      const out = path.join(dir, 'out');
      await fs.writeFile(out, 'file-content');

      const facts = await downloadTree({
        deps: makeDeps(),
        remote: '~/tree',
        localTarget: { path: out, exists: true },
        overwrite: false,
      });
      expect(facts.failure).toMatchObject({ kind: 'Policy', code: 'target_exists' });
      expect(await fs.readFile(out, 'utf8')).toBe('file-content');
    });

    it.skipIf(process.platform === 'win32')(
      'refuses to replace a symlink target when overwrite is true',
      async () => {
        remoteDir();
        state.probeManifest = () => ({ ok: true, entries: [HELLO_ENTRY] });
        const out = path.join(dir, 'out');
        const real = path.join(dir, 'real-dir');
        await fs.mkdir(real);
        await fs.symlink(real, out, 'dir');

        const facts = await downloadTree({
          deps: makeDeps(),
          remote: '~/tree',
          localTarget: { path: out, exists: true },
          overwrite: true,
        });
        expect(facts.failure).toMatchObject({ kind: 'Policy', code: 'target_type_mismatch' });
        expect((await fs.lstat(out)).isSymbolicLink()).toBe(true);
      },
    );

    it('replaces an existing target when overwrite is true and fails on manifest mismatch', async () => {
      remoteDir();
      state.probeManifest = () => ({
        ok: true,
        entries: [HELLO_ENTRY, { ...HELLO_ENTRY, path: 'b.txt' }],
      });
      state.extractFiles = { 'a.txt': { content: Buffer.from('hello'), mode: 0o644 } };
      const out = path.join(dir, 'out');
      await fs.mkdir(out);
      await fs.writeFile(path.join(out, 'old.txt'), 'old');

      const facts = await downloadTree({
        deps: makeDeps(),
        remote: '~/tree',
        localTarget: { path: out, exists: true },
        overwrite: true,
      });
      expect(facts.failure?.code).toBe('verify_manifest_mismatch');
      expect(await fs.readFile(path.join(out, 'old.txt'), 'utf8')).toBe('old');
      expect(await fs.readdir(dir)).toContain('out');
    });
  });
});
