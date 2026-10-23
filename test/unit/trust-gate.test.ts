import { createHash, generateKeyPairSync } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { evaluateTrust } from '../../src/trust/gate.js';
import type { Alias, EffectiveHost, Logger, MCPPaths } from '../../src/types.js';

function makeLogger(): Logger {
  const logger: Logger = {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    child: () => logger,
  };
  return logger;
}

function makePaths(root: string): MCPPaths {
  return {
    configFile: path.join(root, 'config.yaml'),
    configDir: root,
    knownHostsFile: path.join(root, 'known_hosts'),
    trustRegistryFile: path.join(root, 'trust.json'),
    trustLockFile: path.join(root, 'trust.lock'),
    source: 'flag',
  };
}

function makeHost(): EffectiveHost {
  return {
    alias: 'web' as Alias,
    host: 'web.example',
    user: 'deploy',
    port: 22,
    cwd: '~',
    timeouts: { connectMs: 5000, commandMs: 15000, checkMs: 8000 },
    maxOutputBytes: 1024,
    sudo: { mode: 'off', allow: [], deny: [] },
  };
}

function keyMaterial(): { keyBlob: string; fingerprint: string } {
  const { publicKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const algo = Buffer.from('ssh-ed25519');
  const u32 = (n: number): Buffer => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n);
    return b;
  };
  const blob = Buffer.concat([u32(algo.length), algo, u32(raw.length), raw]);
  return {
    keyBlob: blob.toString('base64'),
    fingerprint: `SHA256:${createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`,
  };
}

describe('evaluateTrust', () => {
  let root: string;
  let paths: MCPPaths;
  let log: Logger;
  const host = makeHost();

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-gate-'));
    paths = makePaths(root);
    log = makeLogger();
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await fs.rm(root, { recursive: true, force: true });
  });

  it('fails closed as not_registered when the trust registry is corrupt', async () => {
    await fs.writeFile(paths.trustRegistryFile, '{not valid json', 'utf8');
    const result = await evaluateTrust({ alias: host.alias, host, paths, log });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.fact.reason).toBe('not_registered');
    expect(result.fact.stderr).toContain('trust state could not be read');
    expect(log.warn).toHaveBeenCalled();
  });

  it('reports not_registered without warning when files are simply absent', async () => {
    const result = await evaluateTrust({ alias: host.alias, host, paths, log });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.fact.reason).toBe('not_registered');
    expect(log.warn).not.toHaveBeenCalled();
  });

  it('returns ok when the registry pin matches a known_hosts entry', async () => {
    const key = keyMaterial();
    const pin = {
      algorithm: 'ssh-ed25519',
      keyBlob: key.keyBlob,
      fingerprint: key.fingerprint,
      firstSeenAt: '2026-10-01T00:00:00Z',
      lastVerifiedAt: '2026-10-01T00:00:00Z',
    };
    await fs.writeFile(
      paths.trustRegistryFile,
      JSON.stringify({ version: 1, hosts: { web: pin } }),
      'utf8',
    );
    await fs.writeFile(
      paths.knownHostsFile,
      `web.example ssh-ed25519 ${key.keyBlob}\n`,
      'utf8',
    );

    const result = await evaluateTrust({ alias: host.alias, host, paths, log });
    expect(result).toEqual({ ok: true, pinned: pin });
  });
});
