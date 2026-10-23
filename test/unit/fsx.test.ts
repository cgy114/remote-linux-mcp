import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { atomicWriteFile, ensureDir, readTextIfExists } from '../../src/util/fsx.js';

describe('fsx', () => {
  let root: string;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-fsx-'));
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  describe('atomicWriteFile', () => {
    it('writes content and creates missing parent directories', async () => {
      const file = path.join(root, 'a', 'b', 'config.yaml');
      await atomicWriteFile(file, 'hello: world\n');
      expect(await fs.readFile(file, 'utf8')).toBe('hello: world\n');
    });

    it('overwrites an existing file', async () => {
      const file = path.join(root, 'f.txt');
      await fs.writeFile(file, 'old', 'utf8');
      await atomicWriteFile(file, 'new');
      expect(await fs.readFile(file, 'utf8')).toBe('new');
    });

    it('leaves no temp files behind on success', async () => {
      const file = path.join(root, 'ok.txt');
      await atomicWriteFile(file, 'x');
      const entries = await fs.readdir(root);
      expect(entries).toEqual(['ok.txt']);
    });

    it('cleans up the temp file when rename fails', async () => {
      // 目标是一个非空目录：rename 文件覆盖目录会失败
      const target = path.join(root, 'target');
      await fs.mkdir(target);
      await fs.writeFile(path.join(target, 'keep.txt'), 'k', 'utf8');

      await expect(atomicWriteFile(target, 'data')).rejects.toThrow();

      const entries = await fs.readdir(root);
      expect(entries.filter((n) => n.includes('.tmp-'))).toEqual([]);
      expect(entries).toContain('target');
    });
  });

  describe('readTextIfExists', () => {
    it('returns file content when present', async () => {
      const file = path.join(root, 'r.txt');
      await fs.writeFile(file, 'content', 'utf8');
      expect(await readTextIfExists(file)).toBe('content');
    });

    it('returns undefined when the file does not exist (ENOENT)', async () => {
      expect(await readTextIfExists(path.join(root, 'missing.txt'))).toBeUndefined();
    });

    it('throws for other errors (e.g. reading a directory)', async () => {
      await expect(readTextIfExists(root)).rejects.toThrow();
    });
  });

  describe('ensureDir', () => {
    it('creates nested directories recursively', async () => {
      const dir = path.join(root, 'x', 'y', 'z');
      await ensureDir(dir);
      const st = await fs.stat(dir);
      expect(st.isDirectory()).toBe(true);
    });

    it('does not throw when the directory already exists', async () => {
      await ensureDir(root);
      await expect(ensureDir(root)).resolves.toBeUndefined();
    });
  });
});
