import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { TransferDeps } from '../../../src/transfer/deps.js';

const state = vi.hoisted(() => ({
  path: null as null | ((...args: unknown[]) => Promise<unknown>),
}));

vi.mock('../../../src/transfer/probe.js', () => ({
  probeRemotePath: async (...args: unknown[]) => state.path!(...args),
}));

const { verifyLocalFile, verifyRemoteFile } = await import('../../../src/transfer/verify.js');

const ABC_SHA = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

const deps = {
  limits: { maxFileBytes: 1000, maxFiles: 100, maxTotalBytes: 10000, maxDepth: 10 },
} as unknown as TransferDeps;

describe('verify', () => {
  let root: string;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-verify-'));
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  describe('verifyRemoteFile', () => {
    it('passes when facts match', async () => {
      state.path = async () => ({
        ok: true,
        facts: { path: '~/a', exists: true, type: 'file', size: 3, mode: 0o644, sha256: ABC_SHA },
      });
      await expect(
        verifyRemoteFile(deps, { path: '~/a', sha256: ABC_SHA, bytes: 3, mode: 0o644 }),
      ).resolves.toBeUndefined();
    });

    it('reports each mismatch with a stable code', async () => {
      state.path = async () => ({
        ok: true,
        facts: { path: '~/a', exists: true, type: 'file', size: 4, mode: 0o600 },
      });
      await expect(verifyRemoteFile(deps, { path: '~/a' })).resolves.toBeUndefined();
      expect((await verifyRemoteFile(deps, { path: '~/a', bytes: 3 }))?.code).toBe(
        'verify_size_mismatch',
      );
      expect((await verifyRemoteFile(deps, { path: '~/a', mode: 0o644 }))?.code).toBe(
        'verify_mode_mismatch',
      );
      expect((await verifyRemoteFile(deps, { path: '~/a', sha256: ABC_SHA }))?.code).toBe(
        'verify_sha256_unavailable',
      );
    });

    it('reports missing and non-file paths', async () => {
      state.path = async () => ({ ok: true, facts: { path: '~/a', exists: false } });
      expect((await verifyRemoteFile(deps, { path: '~/a' }))?.code).toBe('verify_missing');
      state.path = async () => ({
        ok: true,
        facts: { path: '~/a', exists: true, type: 'dir', size: 0, mode: 0o755 },
      });
      expect((await verifyRemoteFile(deps, { path: '~/a' }))?.code).toBe('verify_type_mismatch');
    });

    it('passes probe failures through', async () => {
      state.path = async () => ({
        ok: false,
        error: { kind: 'Timeout', code: 'transfer_timeout', message: 'x', retryable: true },
      });
      const failure = await verifyRemoteFile(deps, { path: '~/a' });
      expect(failure?.kind).toBe('Timeout');
    });
  });

  describe('verifyLocalFile', () => {
    it('checks size, mode and sha256', async () => {
      const file = path.join(root, 'a.txt');
      await fs.writeFile(file, 'abc');
      await expect(verifyLocalFile(file, { sha256: ABC_SHA, bytes: 3 })).resolves.toBeUndefined();
      expect((await verifyLocalFile(file, { bytes: 2 }))?.code).toBe('verify_size_mismatch');
      expect((await verifyLocalFile(file, { sha256: '0'.repeat(64) }))?.code).toBe(
        'verify_sha256_mismatch',
      );
      expect((await verifyLocalFile(path.join(root, 'missing'), {}))?.code).toBe('verify_missing');
    });
  });
});
