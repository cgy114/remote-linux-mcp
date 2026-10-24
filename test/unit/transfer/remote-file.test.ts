import { promises as fs } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { TransferDeps } from '../../../src/transfer/deps.js';

const SHA_HELLO = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';

const state = vi.hoisted(() => {
  const mkRun = (exitCode = 0, stdout = '', stderr = '') => ({
    argv: [],
    displayCommand: 'cmd',
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
  });
  return {
    events: [] as string[],
    steps: [] as string[][],
    mkRun,
    probe: ((_target: string) => ({ ok: true, facts: {} })) as (target: string) => unknown,
    verifyInput: undefined as Record<string, unknown> | undefined,
    readRun: (() => mkRun(0)) as () => unknown,
    readCommand: '',
    readMaxOutputBytes: 0,
    sftpRun: (() => mkRun(0)) as () => unknown,
    verifyRemote: (() => undefined) as () => unknown,
    swap: (() => ({ ok: true, backup: '/home/u/.backup', run: mkRun(0), rolledBack: false })) as () => unknown,
    putLocalMode: undefined as number | undefined,
  };
});

vi.mock('../../../src/transfer/probe.js', () => ({
  probeRemotePath: async (_deps: unknown, target: string) => {
    state.events.push(target === '/home/u' ? 'probe-parent' : 'probe');
    return state.probe(target);
  },
  resolveRemoteHome: async () => '/home/u',
}));

vi.mock('../../../src/transfer/deps.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/transfer/deps.js')>();
  return {
    ...actual,
    runRemoteCommand: async (
      _deps: unknown,
      command: string,
      opts: { maxOutputBytes?: number } = {},
    ) => {
      state.events.push('read');
      state.readCommand = command;
      state.readMaxOutputBytes = opts.maxOutputBytes ?? 0;
      return state.readRun();
    },
  };
});

vi.mock('../../../src/transfer/sftp.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/transfer/sftp.js')>();
  const { promises: fsPromises } = await import('node:fs');
  return {
    ...actual,
    runSftpBatch: async (_deps: unknown, steps: readonly string[]) => {
      state.steps.push([...steps]);
      const first = steps[0] ?? '';
      if (first.startsWith('put ')) {
        state.events.push('put');
        const match = /^put "(.*)" "(?:[^"\\]|\\.)*"$/.exec(first);
        if (match !== null) {
          try {
            state.putLocalMode = (await fsPromises.stat(match[1]!)).mode & 0o777;
          } catch {
            state.putLocalMode = undefined;
          }
        }
      } else {
        state.events.push('chmod');
      }
      return state.sftpRun();
    },
  };
});

vi.mock('../../../src/transfer/verify.js', () => ({
  verifyRemoteFile: async (_deps: unknown, input: Record<string, unknown>) => {
    state.events.push('verify');
    state.verifyInput = input;
    return state.verifyRemote();
  },
}));

vi.mock('../../../src/transfer/stage.js', () => ({
  newRemoteTempPath: (target: string) => `${target}.tmp-test`,
  swapRemoteIntoPlace: async () => {
    state.events.push('swap');
    return state.swap();
  },
  removeRemoteTree: async () => ({ ok: true, run: state.mkRun(0) }),
}));

const { readRemoteFile, writeRemoteFile } = await import(
  '../../../src/transfer/remote-file.js'
);

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
    ctx: {
      paths: { configDir: 'C:\\cfg', knownHostsFile: 'C:\\cfg\\known_hosts' },
      log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn(), child: vi.fn() },
      getConfig: async () => {
        throw new Error('not used');
      },
    },
    limits: { maxFileBytes: 1000, maxFiles: 100, maxTotalBytes: 10_000, maxDepth: 10 },
    deadlineMs: Date.now() + 60_000,
    home: '/home/u',
  } as unknown as TransferDeps;
}

function fileFacts(overrides: Record<string, unknown> = {}) {
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

function missingTarget(path = '/home/u/a.txt') {
  return { ok: true, facts: { path, exists: false } };
}

function reset(): void {
  state.events.length = 0;
  state.steps.length = 0;
  state.readCommand = '';
  state.readMaxOutputBytes = 0;
  state.verifyInput = undefined;
  state.probe = (target: string) =>
    target === '/home/u' ? parentDirFacts() : fileFacts();
  state.readRun = () => state.mkRun(0, Buffer.from('hello').toString('base64'));
  state.sftpRun = () => state.mkRun(0);
  state.verifyRemote = () => undefined;
  state.swap = () => ({
    ok: true,
    backup: '/home/u/.backup',
    run: state.mkRun(0),
    rolledBack: false,
  });
  state.putLocalMode = undefined;
}

describe('remote-file state machines', () => {
  beforeEach(() => {
    reset();
  });

  describe('readRemoteFile', () => {
    it('returns UTF-8 text with the full-file sha256 and size', async () => {
      state.probe = () => fileFacts({ size: 5 });
      state.readRun = () => state.mkRun(0, Buffer.from('hello').toString('base64'));
      const facts = await readRemoteFile({
        deps: makeDeps(),
        remote: '~/a.txt',
        maxBytes: 1024,
      });
      expect(facts.ok).toBe(true);
      expect(facts.encoding).toBe('utf8');
      expect(facts.content.toString('utf8')).toBe('hello');
      expect(facts.size).toBe(5);
      expect(facts.returnedBytes).toBe(5);
      expect(facts.truncated).toBe(false);
      expect(facts.sha256).toBe(SHA_HELLO);
      expect(state.readCommand).toContain('cat --');
    });

    it('falls back to base64 for binary content', async () => {
      const binary = Buffer.from([0x00, 0x01, 0xff, 0xfe]);
      state.probe = () => fileFacts({ size: binary.length });
      state.readRun = () => state.mkRun(0, binary.toString('base64'));
      const facts = await readRemoteFile({
        deps: makeDeps(),
        remote: '~/a.bin',
        maxBytes: 1024,
      });
      expect(facts.ok).toBe(true);
      expect(facts.encoding).toBe('base64');
      expect(facts.content.equals(binary)).toBe(true);
    });

    it('uses head -c and marks truncation when the file exceeds max_bytes', async () => {
      state.probe = () => fileFacts({ size: 10 });
      state.readRun = () => state.mkRun(0, Buffer.from('hell').toString('base64'));
      const facts = await readRemoteFile({
        deps: makeDeps(),
        remote: '~/a.txt',
        maxBytes: 4,
      });
      expect(facts.ok).toBe(true);
      expect(state.readCommand).toContain('head -c 4 --');
      expect(facts.returnedBytes).toBe(4);
      expect(facts.truncated).toBe(true);
    });

    it('uses tail -n for tail_lines and caps the output', async () => {
      state.probe = () => fileFacts({ size: 10 });
      state.readRun = () => state.mkRun(0, Buffer.from('b\nc').toString('base64'));
      const facts = await readRemoteFile({
        deps: makeDeps(),
        remote: '~/a.txt',
        maxBytes: 1024,
        tailLines: 2,
      });
      expect(facts.ok).toBe(true);
      expect(state.readCommand).toContain('tail -n 2 --');
      expect(facts.content.toString('utf8')).toBe('b\nc');
      expect(facts.truncated).toBe(true);
    });

    it('rejects invalid base64 from the remote side', async () => {
      state.readRun = () => state.mkRun(0, '!!!!');
      const facts = await readRemoteFile({
        deps: makeDeps(),
        remote: '~/a.txt',
        maxBytes: 1024,
      });
      expect(facts.ok).toBe(false);
      expect(facts.failure?.code).toBe('remote_read_invalid_base64');
    });

    it('enforces the file size limit and rejects symlinks', async () => {
      state.probe = () => fileFacts({ size: 2000 });
      const tooBig = await readRemoteFile({
        deps: makeDeps(),
        remote: '~/a.txt',
        maxBytes: 1024,
      });
      expect(tooBig.failure?.code).toBe('file_too_large');

      state.probe = () => fileFacts({ type: 'symlink' });
      const link = await readRemoteFile({
        deps: makeDeps(),
        remote: '~/a.txt',
        maxBytes: 1024,
      });
      expect(link.failure?.code).toBe('remote_symlink');
      expect(state.events).toEqual(['probe', 'probe']);
    });

    it('fails when the remote hash is unavailable', async () => {
      state.probe = () => fileFacts({ sha256: undefined });
      const facts = await readRemoteFile({
        deps: makeDeps(),
        remote: '~/a.txt',
        maxBytes: 1024,
      });
      expect(facts.failure?.code).toBe('remote_hash_unavailable');
    });
  });

  describe('writeRemoteFile', () => {
    it('puts and chmods in one batch, then verifies and swaps', async () => {
      state.probe = (target: string) =>
        target === '/home/u' ? parentDirFacts() : missingTarget();
      const facts = await writeRemoteFile({
        deps: makeDeps(),
        remote: '~/a.txt',
        content: Buffer.from('hello'),
        encoding: 'utf8',
        mode: 0o640,
        overwrite: false,
      });
      expect(facts.ok).toBe(true);
      expect(facts.bytes).toBe(5);
      expect(facts.sha256).toBe(SHA_HELLO);
      expect(facts.mode).toBe(0o640);
      expect(facts.verified).toBe(true);
      expect(state.events.slice(0, 5)).toEqual(['probe', 'probe-parent', 'put', 'verify', 'swap']);
      // 只跑一次 sftp batch：先 put，再对 staging chmod。
      expect(state.steps).toHaveLength(1);
      expect(state.steps[0]).toHaveLength(2);
      expect(state.steps[0]![0]).toContain('put ');
      expect(state.steps[0]![1]).toContain('chmod 640');
      // mode 在 verify 之前已应用，并随校验一起复核。
      expect(state.verifyInput).toMatchObject({ sha256: SHA_HELLO, bytes: 5, mode: 0o640 });
      if (process.platform !== 'win32') {
        expect(state.putLocalMode).toBe(0o600);
      }
    });

    it('keeps the old mode when mode is omitted', async () => {
      state.probe = () => fileFacts({ mode: 0o600 });
      const facts = await writeRemoteFile({
        deps: makeDeps(),
        remote: '~/a.txt',
        content: Buffer.from('hello'),
        encoding: 'utf8',
        overwrite: true,
      });
      expect(facts.ok).toBe(true);
      expect(facts.mode).toBe(0o600);
      expect(state.steps).toHaveLength(1);
      expect(state.steps[0]![1]).toContain('chmod 600');
    });

    it('rejects a parent realpath denied for writes', async () => {
      state.probe = (target: string) =>
        target === '/home/u' ? parentDirFacts({ realpath: '/etc' }) : missingTarget();
      const facts = await writeRemoteFile({
        deps: makeDeps(),
        remote: '~/new.txt',
        content: Buffer.from('hello'),
        encoding: 'utf8',
        overwrite: false,
      });
      expect(facts.failure).toMatchObject({ kind: 'Policy', code: 'remote_denied_write' });
      expect(state.steps).toHaveLength(0);
      expect(state.events).toEqual(['probe', 'probe-parent']);
    });

    it('rejects a missing parent directory', async () => {
      state.probe = (target: string) =>
        target === '/home/u'
          ? { ok: true, facts: { path: target, exists: false } }
          : missingTarget();
      const facts = await writeRemoteFile({
        deps: makeDeps(),
        remote: '~/new.txt',
        content: Buffer.from('hello'),
        encoding: 'utf8',
        overwrite: false,
      });
      expect(facts.failure).toMatchObject({ kind: 'Policy', code: 'target_parent_missing' });
      expect(state.steps).toHaveLength(0);
    });

    it('refuses an existing target when overwrite is false', async () => {
      const facts = await writeRemoteFile({
        deps: makeDeps(),
        remote: '~/a.txt',
        content: Buffer.from('hello'),
        encoding: 'utf8',
        overwrite: false,
      });
      expect(facts.failure?.code).toBe('target_exists');
      expect(state.events).toEqual(['probe']);
    });

    it('rejects content above the size limit and symlink targets', async () => {
      const tooBig = await writeRemoteFile({
        deps: makeDeps(),
        remote: '~/a.txt',
        content: Buffer.alloc(2000),
        encoding: 'utf8',
        overwrite: false,
      });
      expect(tooBig.failure?.code).toBe('file_too_large');

      state.probe = () => fileFacts({ type: 'symlink' });
      const link = await writeRemoteFile({
        deps: makeDeps(),
        remote: '~/a.txt',
        content: Buffer.from('hello'),
        encoding: 'utf8',
        overwrite: true,
      });
      expect(link.failure?.code).toBe('remote_symlink');
    });

    it('does not swap when verification fails', async () => {
      state.probe = (target: string) =>
        target === '/home/u' ? parentDirFacts() : missingTarget();
      state.verifyRemote = () => ({
        kind: 'RemoteExit',
        code: 'verify_sha256_mismatch',
        message: 'mismatch',
        retryable: false,
      });
      const facts = await writeRemoteFile({
        deps: makeDeps(),
        remote: '~/a.txt',
        content: Buffer.from('hello'),
        encoding: 'utf8',
        overwrite: false,
      });
      expect(facts.ok).toBe(false);
      expect(facts.failure?.code).toBe('verify_sha256_mismatch');
      expect(state.events).toEqual(['probe', 'probe-parent', 'put', 'verify']);
      expect(state.events).not.toContain('swap');
    });
  });
});
