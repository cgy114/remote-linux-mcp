import { createHash, randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { RunResult } from '../../../src/types.js';
import {
  buildRemoteTarCreateCommand,
  createLocalArchive,
  localTarPath,
  resolveLocalTarBinary,
  runLocalTar,
  tarFailure,
} from '../../../src/transfer/tar.js';

/** 测试用本地解包：与 directory.ts 相同，走共用的 tar 解析器。 */
async function extract(
  archive: string,
  destDir: string,
  opts: { gzip?: boolean } = {},
): Promise<RunResult> {
  const binary = await resolveLocalTarBinary();
  return runLocalTar({
    argv: [
      '-C',
      localTarPath(binary, path.resolve(destDir)),
      opts.gzip === true ? '-xzf' : '-xf',
      localTarPath(binary, path.resolve(archive)),
    ],
    binary,
  });
}

function run(overrides: Partial<RunResult> = {}): RunResult {
  return {
    argv: [],
    displayCommand: 'tar',
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
    ...overrides,
  };
}

describe('tar', () => {
  let root: string;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-tar-'));
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  describe('remote commands', () => {
    it('creates an archive of the path itself', () => {
      expect(buildRemoteTarCreateCommand('/home/u/dir')).toBe(
        "tar -C '/home/u' -cf - -- 'dir'",
      );
      expect(buildRemoteTarCreateCommand('~/dir')).toBe("tar -C \"$HOME\" -cf - -- 'dir'");
    });

    it('supports contents and gzip', () => {
      expect(buildRemoteTarCreateCommand('/home/u/dir', { contents: true })).toBe(
        "tar -C '/home/u/dir' -cf - .",
      );
      expect(buildRemoteTarCreateCommand('/home/u/dir', { gzip: true })).toBe(
        "tar -C '/home/u' -czf - -- 'dir'",
      );
    });

    it('refuses to archive a root', () => {
      expect(() => buildRemoteTarCreateCommand('/')).toThrow(
        expect.objectContaining({ code: 'remote_path_invalid' }),
      );
      expect(() => buildRemoteTarCreateCommand('~')).toThrow(
        expect.objectContaining({ code: 'remote_path_invalid' }),
      );
    });
  });

  describe('local roundtrip', () => {
    it('archives and extracts a single file', async () => {
      const file = path.join(root, 'file.txt');
      const archive = path.join(root, 'file.tar');
      const dest = path.join(root, 'dest');
      await fs.writeFile(file, 'hello tar');
      await fs.mkdir(dest);

      const created = await createLocalArchive({ source: file, archive });
      expect(tarFailure(created)).toBeUndefined();

      const extracted = await extract(archive, dest);
      expect(tarFailure(extracted)).toBeUndefined();
      await expect(fs.readFile(path.join(dest, 'file.txt'), 'utf8')).resolves.toBe('hello tar');
    });

    it('archives directory contents', async () => {
      const src = path.join(root, 'src');
      await fs.mkdir(path.join(src, 'nested'), { recursive: true });
      await fs.writeFile(path.join(src, 'a.txt'), 'a');
      await fs.writeFile(path.join(src, 'nested', 'b.txt'), 'b');
      const archive = path.join(root, 'dir.tar');
      const dest = path.join(root, 'dest');
      await fs.mkdir(dest);

      await createLocalArchive({ source: src, archive, contents: true });
      await extract(archive, dest);
      await expect(fs.readFile(path.join(dest, 'a.txt'), 'utf8')).resolves.toBe('a');
      await expect(fs.readFile(path.join(dest, 'nested', 'b.txt'), 'utf8')).resolves.toBe('b');
    });

    it('archives the directory itself when contents is false', async () => {
      const src = path.join(root, 'src');
      await fs.mkdir(src);
      await fs.writeFile(path.join(src, 'a.txt'), 'a');
      const archive = path.join(root, 'dir.tar');
      const dest = path.join(root, 'dest');
      await fs.mkdir(dest);

      await createLocalArchive({ source: src, archive });
      await extract(archive, dest);
      await expect(fs.readFile(path.join(dest, 'src', 'a.txt'), 'utf8')).resolves.toBe('a');
    });

    it('archives a directory larger than the legacy 1 MiB output cap', async () => {
      const src = path.join(root, 'large');
      await fs.mkdir(src);
      const blobs = Array.from({ length: 3 }, () => randomBytes(1024 * 1024));
      for (const [index, blob] of blobs.entries()) {
        await fs.writeFile(path.join(src, `blob-${index}.bin`), blob);
      }
      const archive = path.join(root, 'large.tar');
      const dest = path.join(root, 'large-dest');
      await fs.mkdir(dest);

      // 不传 maxOutputBytes：默认必须是归档上限而不是 1 MiB。
      const created = await createLocalArchive({ source: src, archive, contents: true });
      expect(tarFailure(created)).toBeUndefined();
      expect(created.stdoutTruncated).toBe(false);
      const archiveSize = (await fs.stat(archive)).size;
      console.log(
        `[tar] large archive bytes=${archiveSize} payload=${blobs.length * 1024 * 1024} files=${blobs.length}`,
      );
      expect(archiveSize).toBeGreaterThan(1024 * 1024);

      const extracted = await extract(archive, dest);
      expect(tarFailure(extracted)).toBeUndefined();
      for (const [index, blob] of blobs.entries()) {
        const roundtripped = await fs.readFile(path.join(dest, `blob-${index}.bin`));
        expect(createHash('sha256').update(roundtripped).digest('hex')).toBe(
          createHash('sha256').update(blob).digest('hex'),
        );
      }
    });

    it('roundtrips gzip archives', async () => {
      const file = path.join(root, 'g.txt');
      const archive = path.join(root, 'g.tar.gz');
      const dest = path.join(root, 'dest');
      await fs.writeFile(file, 'gzip');
      await fs.mkdir(dest);

      await createLocalArchive({ source: file, archive, gzip: true });
      await extract(archive, dest, { gzip: true });
      await expect(fs.readFile(path.join(dest, 'g.txt'), 'utf8')).resolves.toBe('gzip');
    });
  });

  describe('resolveLocalTarBinary', () => {
    it('normalizes paths only for GNU tar', () => {
      const gnu = { path: 'tar', argsPrefix: ['--force-local'], gnu: true };
      const system = { path: 'tar', argsPrefix: [], gnu: false };
      expect(localTarPath(gnu, 'C:\\a\\b.tar')).toBe('C:/a/b.tar');
      expect(localTarPath(system, 'C:\\a\\b.tar')).toBe('C:\\a\\b.tar');
    });

    it('returns an absolute binary and uses --force-local for GNU tar', async () => {
      const binary = await resolveLocalTarBinary();
      expect(path.isAbsolute(binary.path)).toBe(true);
      if (binary.gnu) {
        expect(binary.argsPrefix).toEqual(['--force-local']);
      } else {
        expect(binary.argsPrefix).toEqual([]);
      }
    });
  });

  describe('tarFailure', () => {
    it('returns undefined on success', () => {
      expect(tarFailure(run())).toBeUndefined();
    });

    it('maps nonzero exit to tar_failed', () => {
      const failure = tarFailure(run({ exitCode: 2, stderr: 'tar: fatal error' }));
      expect(failure).toMatchObject({ kind: 'RemoteExit', code: 'tar_failed' });
      expect(failure?.details?.['exitCode']).toBe(2);
    });

    it('maps timeout and spawn errors to their categories', () => {
      expect(tarFailure(run({ timedOut: true, exitCode: null }))?.kind).toBe('Timeout');
      expect(
        tarFailure(run({ exitCode: null, spawnError: { code: 'ENOENT', message: 'missing' } }))?.kind,
      ).toBe('Internal');
    });
  });
});
