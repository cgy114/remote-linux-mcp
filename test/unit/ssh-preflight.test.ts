import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { classify } from '../../src/errors/classify.js';
import type { Alias, EffectiveHost, Logger, MCPPaths } from '../../src/types.js';
import { buildChildEnv } from '../../src/ssh/env.js';
import {
  authSignature,
  inspectAgent,
  parseSshAddOutput,
  preflightAuth,
  preflightJump,
} from '../../src/ssh/preflight.js';

const silentLog: Logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  child: () => silentLog,
};

function makeHost(over: Partial<EffectiveHost> = {}): EffectiveHost {
  return {
    alias: 'test-host' as Alias,
    host: 'example.invalid',
    user: 'tester',
    port: 22,
    cwd: '/',
    timeouts: { connectMs: 1000, commandMs: 1000, checkMs: 1000 },
    maxOutputBytes: 65536,
    sudo: { mode: 'off', allow: [], deny: [] },
    ...over,
  };
}

function makePaths(): MCPPaths {
  return {
    configFile: path.join(os.tmpdir(), 'unused-config.yaml'),
    configDir: os.tmpdir(),
    knownHostsFile: path.join(os.tmpdir(), 'unused-known-hosts'),
    trustRegistryFile: path.join(os.tmpdir(), 'unused-registry.json'),
    trustLockFile: path.join(os.tmpdir(), 'unused.lock'),
    source: 'default',
  };
}

describe('authSignature', () => {
  it('sets only auth to true', () => {
    expect(authSignature()).toEqual({
      dns: false,
      tcp: false,
      auth: true,
      hostKeyUnknown: false,
      hostKeyChanged: false,
      sudoPrompt: false,
      connectionTimeout: false,
      other: [],
    });
  });
});

describe('preflightAuth with identityFile', () => {
  let dir: string;
  let readableKey: string;

  beforeAll(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'rmcp-preflight-'));
    readableKey = path.join(dir, 'id_test');
    await fs.writeFile(readableKey, 'not a real key, only readability matters\n');
  });

  afterAll(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it('accepts a readable identity file without consulting the agent', async () => {
    const r = await preflightAuth({
      host: makeHost({ identityFile: readableKey }),
      paths: makePaths(),
      log: silentLog,
    });
    expect(r).toEqual({ ok: true, keySource: 'identity' });
  });

  it('fails with auth signature when identity file is missing on disk', async () => {
    const missing = path.join(dir, 'does-not-exist');
    const r = await preflightAuth({
      host: makeHost({ identityFile: missing }),
      paths: makePaths(),
      log: silentLog,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.fact.phase).toBe('preflight');
    expect(r.fact.signatures).toEqual(authSignature());
    expect(classify(r.fact)).toBe('Auth');
  });
});

describe('preflightAuth without identityFile (depends on local agent)', () => {
  it('returns a structured result and never throws', async () => {
    const r = await preflightAuth({ host: makeHost(), paths: makePaths(), log: silentLog });
    if (r.ok) {
      expect(r.keySource).toBe('agent');
    } else {
      expect(r.fact.phase).toBe('preflight');
      expect(r.fact.signatures).toEqual(authSignature());
      expect(r.fact.stderr).toBe('no usable identity or agent key');
    }
  });
});

describe('parseSshAddOutput', () => {
  it('extracts SHA256 fingerprints from a real-format listing', () => {
    const text =
      '256 SHA256:Xq8r1J2o3kYc4bq5m1Z0nR6sTq7uVwXyZ0123456789a comment@host (ED25519)\n' +
      '2048 SHA256:abcDEF+/ghiJKL0123456789mnopQRSTUVWXYZ0123456 me@laptop (RSA)\n';
    const r = parseSshAddOutput(text);
    expect(r.fingerprints).toEqual([
      'SHA256:Xq8r1J2o3kYc4bq5m1Z0nR6sTq7uVwXyZ0123456789a',
      'SHA256:abcDEF+/ghiJKL0123456789mnopQRSTUVWXYZ0123456',
    ]);
    expect(r.message).toBeUndefined();
  });

  it('returns the no-identities message and no fingerprints', () => {
    const r = parseSshAddOutput('The agent has no identities.\n');
    expect(r.fingerprints).toEqual([]);
    expect(r.message).toBe('The agent has no identities.');
  });

  it('returns empty fingerprints for empty input', () => {
    expect(parseSshAddOutput('')).toEqual({ fingerprints: [] });
  });
});

describe('inspectAgent', () => {
  it('reports unavailable without throwing for a missing ssh-add path', async () => {
    const r = await inspectAgent({
      sshAddPath: path.join(os.tmpdir(), 'definitely-missing-ssh-add.exe'),
      env: buildChildEnv(),
      timeoutMs: 2000,
    });
    expect(r.available).toBe(false);
    expect(r.fingerprints).toEqual([]);
  });
});

describe('preflightJump', () => {
  it('reports an unknown host as not in known_hosts', async () => {
    const r = await preflightJump({
      host: makeHost(),
      jumps: [{ host: 'definitely-not-a-real-host.invalid' }],
      log: silentLog,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.fact.phase).toBe('jump');
    expect(r.fact.reason).toBe('known_hosts_missing');
    expect(r.fact.signatures?.hostKeyUnknown).toBe(true);
    expect(classify(r.fact)).toBe('HostKey');
  });

  it('succeeds with no jumps', async () => {
    expect(await preflightJump({ host: makeHost(), jumps: [], log: silentLog })).toEqual({ ok: true });
  });

  it('does not throw for localhost (result not forced)', async () => {
    const r = await preflightJump({
      host: makeHost(),
      jumps: [{ host: 'localhost' }],
      log: silentLog,
    });
    expect(typeof r.ok).toBe('boolean');
  });
});
