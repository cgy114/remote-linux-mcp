import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  assertDepth,
  assertFileCount,
  assertFileSize,
  assertTotalBytes,
  assertTransferEnabled,
  fileLimitsFrom,
  type FileLimits,
} from '../../../src/transfer/file-policy.js';
import {
  buildLocalManifest,
  expandLocalPath,
  isLocalContained,
  newLocalTempPath,
  resolveLocalSource,
  resolveLocalTarget,
} from '../../../src/transfer/local-path.js';

const LIMITS: FileLimits = {
  maxFileBytes: 1_000_000,
  maxFiles: 100,
  maxTotalBytes: 10_000_000,
  maxDepth: 10,
};

const IS_WIN = process.platform === 'win32';

function linkType(): 'junction' | 'dir' {
  return IS_WIN ? 'junction' : 'dir';
}

async function makeDirLink(target: string, link: string): Promise<void> {
  await fs.symlink(target, link, linkType());
}

describe('file-policy', () => {
  it('extracts limits from FilesConfig', () => {
    expect(
      fileLimitsFrom({
        localRoots: [],
        remoteDeny: [],
        maxFileBytes: 1,
        maxFiles: 2,
        maxTotalBytes: 3,
        maxDepth: 4,
        transferTimeoutMs: 5,
      }),
    ).toEqual({ maxFileBytes: 1, maxFiles: 2, maxTotalBytes: 3, maxDepth: 4 });
  });

  it('enforces each limit with a stable code', () => {
    expect(() => assertFileSize(11, LIMITS)).not.toThrow();
    expect(() => assertFileSize(1_000_001, LIMITS)).toThrow(
      expect.objectContaining({ code: 'file_too_large' }),
    );
    expect(() => assertFileCount(101, LIMITS)).toThrow(
      expect.objectContaining({ code: 'too_many_files' }),
    );
    expect(() => assertTotalBytes(10_000_001, LIMITS)).toThrow(
      expect.objectContaining({ code: 'total_too_large' }),
    );
    expect(() => assertDepth(11, LIMITS)).toThrow(
      expect.objectContaining({ code: 'depth_too_deep' }),
    );
  });

  it('disables transfer when localRoots is empty', () => {
    expect(() => assertTransferEnabled({ localRoots: ['/srv'] })).not.toThrow();
    expect(() => assertTransferEnabled({ localRoots: [] })).toThrow(
      expect.objectContaining({ code: 'transfer_disabled' }),
    );
  });
});

describe('local-path', () => {
  let root: string;
  let outside: string;

  beforeEach(async () => {
    const base = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-local-'));
    root = path.join(base, 'root');
    outside = path.join(base, 'outside');
    await fs.mkdir(root);
    await fs.mkdir(outside);
  });

  afterEach(async () => {
    await fs.rm(path.dirname(root), { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  describe('containment', () => {
    it('accepts root and descendants, rejects siblings and parents', () => {
      expect(isLocalContained(root, root)).toBe(true);
      expect(isLocalContained(root, path.join(root, 'a', 'b'))).toBe(true);
      expect(isLocalContained(root, outside)).toBe(false);
      expect(isLocalContained(root, path.join(root, '..', 'outside'))).toBe(false);
    });

    it('folds case on Windows only', () => {
      if (IS_WIN) {
        expect(isLocalContained('C:\\Root', 'c:\\root\\x')).toBe(true);
      } else {
        expect(isLocalContained('/tmp/Root', '/tmp/root/x')).toBe(false);
      }
    });

    it('expands home and rejects ~user', () => {
      expect(expandLocalPath('~/x', '/home/u')).toBe(path.join('/home/u', 'x'));
      expect(expandLocalPath('~', '/home/u')).toBe('/home/u');
      expect(() => expandLocalPath('~user/x', '/home/u')).toThrow(
        expect.objectContaining({ code: 'local_path_invalid' }),
      );
    });
  });

  describe('resolveLocalSource', () => {
    it('accepts a regular file inside the roots', async () => {
      const file = path.join(root, 'a.txt');
      await fs.writeFile(file, 'abc');
      const source = await resolveLocalSource({ path: file, limits: LIMITS, roots: [root] });
      expect(source.kind).toBe('file');
      expect(source.size).toBe(3);
      expect(source.realPath).toBe(await fs.realpath(file));
    });

    it('expands ~ against the injected home', async () => {
      await fs.writeFile(path.join(root, 'h.txt'), 'x');
      const source = await resolveLocalSource({
        path: '~/h.txt',
        limits: LIMITS,
        roots: [root],
        home: root,
      });
      expect(source.path).toBe(path.join(root, 'h.txt'));
    });

    it('rejects directories unless allowDir', async () => {
      await expect(
        resolveLocalSource({ path: root, limits: LIMITS, roots: [root] }),
      ).rejects.toMatchObject({ code: 'local_invalid_type' });
      const source = await resolveLocalSource({
        path: root,
        limits: LIMITS,
        roots: [root],
        allowDir: true,
      });
      expect(source.kind).toBe('dir');
    });

    it('rejects missing sources and oversize files', async () => {
      await expect(
        resolveLocalSource({ path: path.join(root, 'nope'), limits: LIMITS, roots: [root] }),
      ).rejects.toMatchObject({ code: 'local_source_not_found' });
      const big = path.join(root, 'big');
      await fs.writeFile(big, Buffer.alloc(4));
      await expect(
        resolveLocalSource({
          path: big,
          limits: { ...LIMITS, maxFileBytes: 3 },
          roots: [root],
        }),
      ).rejects.toMatchObject({ code: 'file_too_large' });
    });

    it('rejects a symlink target and a realpath escape through a symlinked parent', async () => {
      await fs.writeFile(path.join(outside, 'secret.txt'), 'secret');
      const link = path.join(root, 'link');
      await makeDirLink(outside, link);

      await expect(
        resolveLocalSource({ path: link, limits: LIMITS, roots: [root] }),
      ).rejects.toMatchObject({ code: 'local_symlink' });

      await expect(
        resolveLocalSource({
          path: path.join(link, 'secret.txt'),
          limits: LIMITS,
          roots: [root],
        }),
      ).rejects.toMatchObject({ code: 'local_root_not_allowed' });
    });

    it('rejects paths outside the roots', async () => {
      const file = path.join(outside, 'x.txt');
      await fs.writeFile(file, 'x');
      await expect(
        resolveLocalSource({ path: file, limits: LIMITS, roots: [root] }),
      ).rejects.toMatchObject({ code: 'local_root_not_allowed' });
    });
  });

  describe('resolveLocalTarget', () => {
    it('accepts a new file whose parent is inside the roots', async () => {
      const target = await resolveLocalTarget({
        path: path.join(root, 'new.txt'),
        limits: LIMITS,
        roots: [root],
      });
      expect(target.exists).toBe(false);
      expect(target.path).toBe(path.join(root, 'new.txt'));
    });

    it('requires an existing parent inside the roots', async () => {
      await expect(
        resolveLocalTarget({
          path: path.join(root, 'missing', 'x.txt'),
          limits: LIMITS,
          roots: [root],
        }),
      ).rejects.toMatchObject({ code: 'local_parent_missing' });
      await expect(
        resolveLocalTarget({ path: path.join(outside, 'x.txt'), limits: LIMITS, roots: [root] }),
      ).rejects.toMatchObject({ code: 'local_root_not_allowed' });
    });

    it('enforces overwrite and type rules', async () => {
      const file = path.join(root, 'exists.txt');
      await fs.writeFile(file, 'abc');
      await expect(
        resolveLocalTarget({ path: file, limits: LIMITS, roots: [root] }),
      ).rejects.toMatchObject({ code: 'target_exists' });
      const target = await resolveLocalTarget({
        path: file,
        limits: LIMITS,
        roots: [root],
        overwrite: true,
      });
      expect(target.exists).toBe(true);
      expect(target.kind).toBe('file');

      const sub = path.join(root, 'subdir');
      await fs.mkdir(sub);
      await expect(
        resolveLocalTarget({ path: sub, limits: LIMITS, roots: [root], overwrite: true }),
      ).rejects.toMatchObject({ code: 'local_invalid_type' });
      const dirTarget = await resolveLocalTarget({
        path: sub,
        limits: LIMITS,
        roots: [root],
        overwrite: true,
        allowDir: true,
      });
      expect(dirTarget.kind).toBe('dir');
    });

    it('rejects an existing symlink target', async () => {
      const link = path.join(root, 'target-link');
      await makeDirLink(outside, link);
      await expect(
        resolveLocalTarget({ path: link, limits: LIMITS, roots: [root], overwrite: true, allowDir: true }),
      ).rejects.toMatchObject({ code: 'local_symlink' });
    });
  });

  it('creates same-directory temp paths', () => {
    const t1 = newLocalTempPath(root, 'download');
    const t2 = newLocalTempPath(root, 'download');
    expect(path.dirname(t1)).toBe(root);
    expect(path.basename(t1)).toMatch(/^\.remote-mcp-download-[0-9a-f]{16}$/);
    expect(t1).not.toBe(t2);
    expect(() => newLocalTempPath(root, 'Bad Kind')).toThrow(
      expect.objectContaining({ code: 'local_path_invalid' }),
    );
  });

  describe('buildLocalManifest', () => {
    it('hashes files, masks modes and sorts entries', async () => {
      await fs.writeFile(path.join(root, 'a.txt'), 'abc');
      await fs.mkdir(path.join(root, 'sub'));
      await fs.writeFile(path.join(root, 'sub', 'b.txt'), 'hello');
      const entries = await buildLocalManifest({ root, limits: LIMITS });
      expect(entries.map((entry) => entry.path)).toEqual(['a.txt', 'sub', 'sub/b.txt']);
      const a = entries[0]!;
      expect(a.type).toBe('file');
      expect(a.mode).toBe((await fs.lstat(path.join(root, 'a.txt'))).mode & 0o777);
      expect(a.sha256).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
      expect(entries[1]).toMatchObject({ type: 'dir', size: 0 });
      expect(entries[2]!.sha256).toMatch(/^[0-9a-f]{64}$/);
    });

    it('does not follow symlinks and records their targets', async () => {
      await fs.writeFile(path.join(outside, 'secret.txt'), 'secret');
      await fs.writeFile(path.join(root, 'ok.txt'), 'ok');
      await makeDirLink(outside, path.join(root, 'link'));
      const entries = await buildLocalManifest({ root, limits: LIMITS });
      expect(entries.map((entry) => entry.path)).toEqual(['link', 'ok.txt']);
      const link = entries.find((entry) => entry.path === 'link');
      expect(link?.type).toBe('symlink');
      expect(link?.size).toBe(0);
      expect(link?.linkTarget).toBeTruthy();
      expect(entries.some((entry) => entry.path.includes('secret'))).toBe(false);
    });

    it('can skip hashing', async () => {
      await fs.writeFile(path.join(root, 'a.txt'), 'abc');
      const entries = await buildLocalManifest({ root, limits: LIMITS, hash: false });
      expect(entries[0]!.sha256).toBeUndefined();
    });

    it('returns a single "." entry for a file root', async () => {
      const file = path.join(root, 'single.txt');
      await fs.writeFile(file, 'abc');
      const entries = await buildLocalManifest({ root: file, limits: LIMITS });
      expect(entries).toHaveLength(1);
      expect(entries[0]).toMatchObject({ path: '.', type: 'file', size: 3 });
    });

    it('enforces file count, total bytes, depth and file size', async () => {
      await fs.writeFile(path.join(root, 'a.txt'), 'aaaa');
      await fs.writeFile(path.join(root, 'b.txt'), 'bbbb');
      await expect(
        buildLocalManifest({ root, limits: { ...LIMITS, maxFiles: 1 } }),
      ).rejects.toMatchObject({ code: 'too_many_files' });
      await expect(
        buildLocalManifest({ root, limits: { ...LIMITS, maxTotalBytes: 7 } }),
      ).rejects.toMatchObject({ code: 'total_too_large' });
      await expect(
        buildLocalManifest({ root, limits: { ...LIMITS, maxFileBytes: 3 } }),
      ).rejects.toMatchObject({ code: 'file_too_large' });

      await fs.mkdir(path.join(root, 'sub'));
      await fs.writeFile(path.join(root, 'sub', 'c.txt'), 'c');
      await expect(
        buildLocalManifest({ root, limits: { ...LIMITS, maxDepth: 1 } }),
      ).rejects.toMatchObject({ code: 'depth_too_deep' });
    });
  });
});
