import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';
import type { Alias, EffectiveHost, Logger, MCPPaths, PinnedHostKey, TrustRegistry } from '../../src/types.js';
import { decideTrust } from '../../src/trust/decision.js';
import { fingerprintKey } from '../../src/trust/fingerprint.js';
import {
  confirmTrust,
  renderTrustPreview,
  runTrustFlow,
  type TrustFlowDeps,
} from '../../src/trust/flow.js';

const silentLog: Logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  child: () => silentLog,
};

const ALIAS = 'web-1' as Alias;
const T0 = '2026-02-01T00:00:00.000Z';

function pinFrom(seed: string, firstSeenAt = '2025-12-01T00:00:00.000Z'): PinnedHostKey {
  const keyBlob = Buffer.from(`flow-key-${seed}`).toString('base64');
  return {
    algorithm: 'ssh-ed25519',
    keyBlob,
    fingerprint: fingerprintKey('ssh-ed25519', keyBlob),
    firstSeenAt,
    lastVerifiedAt: firstSeenAt,
  };
}

function hostFixture(): EffectiveHost {
  return {
    alias: ALIAS,
    host: 'web1.example.invalid',
    user: 'deploy',
    port: 2222,
    cwd: '/',
    timeouts: { connectMs: 1000, commandMs: 1000, checkMs: 1000 },
    maxOutputBytes: 65536,
    sudo: { mode: 'off', allow: [], deny: [] },
  };
}

const PATHS: MCPPaths = {
  configFile: '/x/config.yml',
  configDir: '/x',
  knownHostsFile: '/x/known_hosts',
  trustRegistryFile: '/x/registry.json',
  trustLockFile: '/x/trust.lock',
  source: 'flag',
};

function makeDeps(over: Partial<TrustFlowDeps> & { registry?: TrustRegistry; observedSeed?: string } = {}) {
  const observedSeed = over.observedSeed ?? 'server-A';
  const observedBlob = Buffer.from(`flow-key-${observedSeed}`).toString('base64');
  const registry: { current: TrustRegistry } = { current: over.registry ?? { version: 1, hosts: {} } };
  const calls = {
    writeKnownHosts: [] as unknown[],
    saveRegistry: [] as TrustRegistry[],
    confirm: 0,
    acquireLock: 0,
    release: 0,
    verify: 0,
  };
  const deps: Partial<TrustFlowDeps> = {
    preflightAuth: async () => ({ ok: true, keySource: 'agent' }),
    preflightJump: async () => ({ ok: true }),
    probeHostKey: async () => ({
      ok: true,
      tempFile: '/tmp/x',
      entries: [
        {
          marker: null,
          hosts: ['[web1.example.invalid]:2222'],
          algorithm: 'ssh-ed25519',
          keyBlob: observedBlob,
          raw: 'x',
          line: 1,
        },
      ],
    }),
    verifyTrustedConnection: async () => {
      calls.verify++;
      return { ok: true };
    },
    loadRegistry: async () => structuredClone(registry.current),
    saveRegistry: async (_f, reg) => {
      calls.saveRegistry.push(reg);
      registry.current = reg;
    },
    acquireLock: async () => {
      calls.acquireLock++;
      return async () => {
        calls.release++;
      };
    },
    writeKnownHosts: async (input) => {
      calls.writeKnownHosts.push(input);
    },
    confirm: async () => {
      calls.confirm++;
      return { ok: true };
    },
    render: renderTrustPreview,
    ...over,
  };
  return { deps, calls, registry, observedBlob, observedFp: fingerprintKey('ssh-ed25519', observedBlob) };
}

const NOW = () => new Date(T0);

// ---------- decideTrust ----------

describe('decideTrust', () => {
  const observed = pinFrom('new');
  const old = pinFrom('old', '2025-06-01T00:00:00.000Z');

  it('no pinned -> initial', () => {
    expect(decideTrust({ alias: ALIAS, observed, rotate: false }).action).toBe('initial');
    expect(decideTrust({ alias: ALIAS, observed, rotate: true }).action).toBe('initial');
  });

  it('same fingerprint -> unchanged, pinned passed through as-is', () => {
    const same = { ...observed, firstSeenAt: '2000-01-01T00:00:00.000Z' };
    const d = decideTrust({ alias: ALIAS, observed, pinned: same, rotate: false });
    expect(d.action).toBe('unchanged');
    expect(d.pinned).toBe(same);
  });

  it('different fingerprint + rotate -> rotate', () => {
    const d = decideTrust({ alias: ALIAS, observed, pinned: old, rotate: true });
    expect(d.action).toBe('rotate');
    expect(d.pinned).toBe(old);
  });

  it('different fingerprint, no rotate -> reject with fingerprint_mismatch', () => {
    const d = decideTrust({ alias: ALIAS, observed, pinned: old, rotate: false });
    expect(d.action).toBe('reject');
    expect(d.reason).toBe('fingerprint_mismatch');
  });
});

// ---------- confirmTrust ----------

describe('confirmTrust', () => {
  const observed = pinFrom('c');

  function stdinWith(text: string | null): PassThrough {
    const s = new PassThrough();
    if (text !== null) s.end(text);
    else s.end();
    return s;
  }

  it('interactive: exact "yes" (after trim) is accepted and preview is written', async () => {
    const out = new PassThrough();
    let written = '';
    out.on('data', (c: Buffer) => (written += c.toString('utf8')));
    const res = await confirmTrust({
      preview: 'PREVIEW-BLOCK',
      interactive: true,
      observed,
      stdin: stdinWith('  yes  \n'),
      stdout: out,
    });
    expect(res).toEqual({ ok: true });
    expect(written).toContain('PREVIEW-BLOCK');
    expect(written).toContain('Type "yes" to trust this host: ');
  });

  it('interactive: other inputs are declined', async () => {
    for (const input of ['y\n', 'YES\n', 'yes please\n', '\n']) {
      const res = await confirmTrust({
        preview: 'p',
        interactive: true,
        observed,
        stdin: stdinWith(input),
        stdout: new PassThrough(),
      });
      expect(res, JSON.stringify(input)).toEqual({ ok: false, reason: 'declined' });
    }
  });

  it('interactive: EOF without a line is declined', async () => {
    const res = await confirmTrust({
      preview: 'p',
      interactive: true,
      observed,
      stdin: stdinWith(null),
      stdout: new PassThrough(),
    });
    expect(res).toEqual({ ok: false, reason: 'declined' });
  });

  it('interactive: timeout is declined (short injected timeout)', async () => {
    const res = await confirmTrust({
      preview: 'p',
      interactive: true,
      observed,
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      timeoutMs: 30,
    });
    expect(res).toEqual({ ok: false, reason: 'declined' });
  });

  it('non-interactive: exact full fingerprint matches', async () => {
    expect(
      await confirmTrust({ preview: 'p', interactive: false, assumedFingerprint: observed.fingerprint, observed }),
    ).toEqual({ ok: true });
  });

  it('non-interactive: missing, prefix-omitted, case-changed or wrong fingerprint -> fingerprint_mismatch', async () => {
    const bare = observed.fingerprint.slice('SHA256:'.length);
    for (const assumed of [undefined, bare, observed.fingerprint.toLowerCase(), 'SHA256:wrong']) {
      expect(await confirmTrust({ preview: 'p', interactive: false, assumedFingerprint: assumed, observed })).toEqual({
        ok: false,
        reason: 'fingerprint_mismatch',
      });
    }
  });
});

// ---------- renderTrustPreview ----------

describe('renderTrustPreview', () => {
  it('includes alias, target, algorithm, new fingerprint and the server-side comparison command', () => {
    const observed = pinFrom('r-new');
    const text = renderTrustPreview({
      alias: ALIAS,
      host: hostFixture(),
      decision: { action: 'initial', observed },
    });
    expect(text).toContain(ALIAS);
    expect(text).toContain('deploy@web1.example.invalid:2222');
    expect(text).toContain('ssh-ed25519');
    expect(text).toContain(observed.fingerprint);
    expect(text).toContain('ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub');
    expect(text).not.toContain('旧指纹');
  });

  it('for rotate shows both old and new fingerprints', () => {
    const observed = pinFrom('r-new');
    const pinned = pinFrom('r-old');
    const text = renderTrustPreview({
      alias: ALIAS,
      host: hostFixture(),
      decision: { action: 'rotate', observed, pinned },
    });
    expect(text).toContain(observed.fingerprint);
    expect(text).toContain(pinned.fingerprint);
    expect(text).toContain('ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub');
  });
});

// ---------- runTrustFlow ----------

describe('runTrustFlow', () => {
  it('initial success: writes known_hosts once, saves registry, releases lock, verifies', async () => {
    const { deps, calls, observedFp } = makeDeps();
    const out = await runTrustFlow({
      host: hostFixture(),
      paths: PATHS,
      rotate: false,
      interactive: true,
      log: silentLog,
      now: NOW,
      deps,
    });
    expect(out.ok).toBe(true);
    expect(out.action).toBe('initial');
    expect(out.message).toContain(observedFp);
    expect(calls.writeKnownHosts).toHaveLength(1);
    expect(calls.writeKnownHosts[0]).toMatchObject({
      file: PATHS.knownHostsFile,
      host: 'web1.example.invalid',
      port: 2222,
      algorithm: 'ssh-ed25519',
      mode: 'replace-host',
    });
    expect(calls.saveRegistry).toHaveLength(1);
    expect(calls.saveRegistry[0]!.hosts[ALIAS]).toMatchObject({
      fingerprint: observedFp,
      firstSeenAt: T0,
      lastVerifiedAt: T0,
    });
    expect(calls.release).toBe(1);
    expect(calls.verify).toBe(1);
  });

  it('reject: fingerprint differs and no rotate -> rejected, nothing written, message has both fingerprints and --rotate', async () => {
    const pinned = pinFrom('pinned-old');
    const { deps, calls, observedFp } = makeDeps({
      registry: { version: 1, hosts: { [ALIAS]: pinned } },
      observedSeed: 'server-new',
    });
    const out = await runTrustFlow({
      host: hostFixture(),
      paths: PATHS,
      rotate: false,
      interactive: true,
      log: silentLog,
      now: NOW,
      deps,
    });
    expect(out.ok).toBe(false);
    expect(out.action).toBe('rejected');
    expect(out.message).toContain(pinned.fingerprint);
    expect(out.message).toContain(observedFp);
    expect(out.message).toContain('--rotate');
    expect(calls.writeKnownHosts).toHaveLength(0);
    expect(calls.saveRegistry).toHaveLength(0);
    expect(calls.confirm).toBe(0);
    expect(calls.acquireLock).toBe(0);
  });

  it('declined: user does not confirm -> declined, nothing written, lock never taken', async () => {
    const { deps, calls } = makeDeps({ confirm: async () => ({ ok: false, reason: 'declined' }) });
    const out = await runTrustFlow({
      host: hostFixture(),
      paths: PATHS,
      rotate: false,
      interactive: true,
      log: silentLog,
      now: NOW,
      deps,
    });
    expect(out.ok).toBe(false);
    expect(out.action).toBe('declined');
    expect(out.message).toContain('未写入');
    expect(calls.writeKnownHosts).toHaveLength(0);
    expect(calls.saveRegistry).toHaveLength(0);
    expect(calls.acquireLock).toBe(0);
  });

  it('unchanged: same fingerprint pinned -> verify and ok unchanged, no writes', async () => {
    const { deps, calls, observedFp } = makeDeps({
      registry: { version: 1, hosts: { [ALIAS]: pinFrom('server-A') } },
    });
    expect(observedFp).toBe(pinFrom('server-A').fingerprint);
    const out = await runTrustFlow({
      host: hostFixture(),
      paths: PATHS,
      rotate: false,
      interactive: true,
      log: silentLog,
      now: NOW,
      deps,
    });
    expect(out.ok).toBe(true);
    expect(out.action).toBe('unchanged');
    expect(calls.verify).toBe(1);
    expect(calls.writeKnownHosts).toHaveLength(0);
    expect(calls.confirm).toBe(0);
  });

  it('unchanged but verification fails -> ok false, action failed', async () => {
    const { deps } = makeDeps({
      registry: { version: 1, hosts: { [ALIAS]: pinFrom('server-A') } },
      verifyTrustedConnection: async () => ({
        ok: false,
        fact: { phase: 'verify', reason: 'ssh_transport_failure', exitCode: 255, stderr: 'Permission denied (publickey).' },
      }),
    });
    const out = await runTrustFlow({
      host: hostFixture(),
      paths: PATHS,
      rotate: false,
      interactive: true,
      log: silentLog,
      now: NOW,
      deps,
    });
    expect(out.ok).toBe(false);
    expect(out.action).toBe('failed');
    expect(out.message).toContain('认证验证失败');
  });

  it('write succeeds but final verification fails -> message explicitly says fingerprint written but auth verify failed', async () => {
    const { deps, calls } = makeDeps({
      verifyTrustedConnection: async () => ({
        ok: false,
        fact: { phase: 'verify', reason: 'ssh_transport_failure', exitCode: 255, stderr: 'Permission denied (publickey).' },
      }),
    });
    const out = await runTrustFlow({
      host: hostFixture(),
      paths: PATHS,
      rotate: false,
      interactive: true,
      log: silentLog,
      now: NOW,
      deps,
    });
    expect(out.ok).toBe(false);
    expect(out.message).toContain('指纹已写入，但认证验证失败');
    expect(calls.writeKnownHosts).toHaveLength(1);
    expect(calls.saveRegistry).toHaveLength(1);
  });

  it('auth preflight failure refuses trust and says why', async () => {
    const { deps, calls } = makeDeps({
      preflightAuth: async () => ({
        ok: false,
        fact: { phase: 'preflight', reason: 'internal', stderr: 'no usable identity or agent key' },
      }),
    });
    const out = await runTrustFlow({
      host: hostFixture(),
      paths: PATHS,
      rotate: false,
      interactive: true,
      log: silentLog,
      now: NOW,
      deps,
    });
    expect(out.ok).toBe(false);
    expect(out.message).toContain('认证前置检查失败');
    expect(calls.writeKnownHosts).toHaveLength(0);
  });

  it('rotate success keeps the original firstSeenAt', async () => {
    const pinned = pinFrom('old-key', '2024-03-03T00:00:00.000Z');
    const { deps, calls, observedFp } = makeDeps({
      registry: { version: 1, hosts: { [ALIAS]: pinned } },
      observedSeed: 'rotated-key',
    });
    const out = await runTrustFlow({
      host: hostFixture(),
      paths: PATHS,
      rotate: true,
      interactive: true,
      log: silentLog,
      now: NOW,
      deps,
    });
    expect(out.ok).toBe(true);
    expect(out.action).toBe('rotate');
    const saved = calls.saveRegistry[0]!.hosts[ALIAS]!;
    expect(saved.fingerprint).toBe(observedFp);
    expect(saved.firstSeenAt).toBe('2024-03-03T00:00:00.000Z');
    expect(saved.lastVerifiedAt).toBe(T0);
  });

  it('never throws: a dependency exception becomes ok false with a ToolError', async () => {
    const { deps, calls } = makeDeps({
      saveRegistry: async () => {
        throw new Error('disk full');
      },
    });
    const out = await runTrustFlow({
      host: hostFixture(),
      paths: PATHS,
      rotate: false,
      interactive: true,
      log: silentLog,
      now: NOW,
      deps,
    });
    expect(out.ok).toBe(false);
    expect(out.error?.kind).toBeDefined();
    expect(out.message).toContain('disk full');
    expect(calls.release).toBe(1); // finally 仍释放锁
  });

  it('non-interactive with mismatched --fingerprint -> declined and nothing written', async () => {
    const { deps, calls } = makeDeps({ confirm: confirmTrust });
    const out = await runTrustFlow({
      host: hostFixture(),
      paths: PATHS,
      rotate: false,
      interactive: false,
      assumedFingerprint: 'SHA256:nope',
      log: silentLog,
      now: NOW,
      deps,
    });
    expect(out.ok).toBe(false);
    expect(out.action).toBe('declined');
    expect(calls.writeKnownHosts).toHaveLength(0);
  });
});
