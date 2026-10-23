import { createHash, generateKeyPairSync } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ConfigError, UsageError } from '../../src/errors/classes.js';
import { assertAlias } from '../../src/policy/alias.js';
import {
  assertCwd,
  assertHostString,
  assertPort,
  assertTarget,
  assertUser,
  checkTrustState,
  describeHost,
  effectiveHost,
  resolveIdentityFile,
  selectJumpSpec,
} from '../../src/policy/target.js';
import {
  assertArgvSafe,
  baseSshOptions,
  buildSshArgv,
  buildSshGArgv,
} from '../../src/policy/argv.js';
import type {
  Alias,
  EffectiveHost,
  KnownHostEntry,
  PinnedHostKey,
  RemoteConfig,
  TrustRegistry,
} from '../../src/types.js';

/** Returns the `code` of the thrown error, or undefined when nothing throws. */
function codeOf(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (e) {
    return (e as { code?: string }).code ?? 'NO_CODE';
  }
  return undefined;
}

const KH = path.resolve('policy-test', 'known_hosts');

function makeHost(overrides: Partial<EffectiveHost> = {}): EffectiveHost {
  return {
    alias: 'web' as Alias,
    host: 'web.example',
    user: 'deploy',
    port: 2222,
    cwd: '/home/deploy',
    timeouts: { connectMs: 5000, commandMs: 60000, checkMs: 10000 },
    maxOutputBytes: 1024,
    sudo: { mode: 'off', allow: [], deny: [] },
    ...overrides,
  };
}

function makeConfig(baseDir: string): RemoteConfig {
  return {
    version: 1,
    sourcePath: path.join(baseDir, 'config.yaml'),
    baseDir,
    defaults: {
      port: 2222,
      defaultCwd: '/home/x',
      timeouts: { connectMs: 5000, commandMs: 60000, checkMs: 10000 },
      maxOutputBytes: 4096,
      sudo: { mode: 'off', allow: ['systemctl'], deny: [] },
    },
    security: { hostKeyPolicy: 'pinned' },
    hosts: {
      web: { host: 'web.example', user: 'deploy' },
      db: {
        host: 'db',
        user: 'ops',
        port: 22,
        defaultCwd: '/var',
        identityFile: 'keys/db',
        proxyJump: 'bastion',
      },
    },
  };
}

describe('assertAlias', () => {
  it('accepts valid aliases', () => {
    for (const ok of ['a', 'prod', 'web-1.eu_2', 'x'.repeat(64)]) {
      expect(assertAlias(ok)).toBe(ok);
    }
  });

  it('rejects uppercase, leading "-", spaces, over-length, and reserved words', () => {
    for (const bad of ['Prod', '-web', '.web', 'web host', 'x'.repeat(65), 'default', 'serve', 'trust']) {
      expect(codeOf(() => assertAlias(bad))).toBe('invalid_alias');
    }
  });

  it('rejects non-strings and throws a UsageError with code', () => {
    expect(codeOf(() => assertAlias(1))).toBe('invalid_alias');
    expect(codeOf(() => assertAlias(null))).toBe('invalid_alias');
    try {
      assertAlias('Bad');
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(UsageError);
      expect((e as UsageError).code).toBe('invalid_alias');
    }
  });
});

describe('assertHostString', () => {
  it('accepts names, IPv4 and IPv6 literals', () => {
    for (const ok of ['example.com', '10.0.0.1', '::1', 'a'.repeat(255)]) {
      expect(assertHostString(ok)).toBe(ok);
    }
  });

  it('rejects option-injection, whitespace, "@", "/", empty and over-length', () => {
    const bad = ['-oProxyCommand=x', 'a b', 'user@host', 'a/b', '', 'a'.repeat(256), 'a\tb', 'a\nb'];
    for (const v of bad) {
      expect(codeOf(() => assertHostString(v))).toBe('invalid_host');
    }
  });
});

describe('assertUser', () => {
  it('accepts allowed user names', () => {
    expect(assertUser('deploy')).toBe('deploy');
    expect(assertUser('a.b-c_d')).toBe('a.b-c_d');
    expect(assertUser('x'.repeat(64))).toBe('x'.repeat(64));
  });

  it('rejects empty, over-length, bad characters and leading "-"', () => {
    for (const bad of ['', 'x'.repeat(65), 'a b', 'a@b', '-root', 'a/b']) {
      expect(codeOf(() => assertUser(bad))).toBe('invalid_user');
    }
  });
});

describe('assertPort', () => {
  it('accepts integers 1-65535', () => {
    expect(assertPort(1)).toBe(1);
    expect(assertPort(22)).toBe(22);
    expect(assertPort(65535)).toBe(65535);
  });

  it('rejects strings, 0, 65536, fractions and NaN', () => {
    for (const bad of ['22', 0, 65536, 1.5, Number.NaN, null]) {
      expect(codeOf(() => assertPort(bad))).toBe('invalid_port');
    }
  });
});

describe('assertCwd', () => {
  it('accepts absolute and ~ paths', () => {
    expect(assertCwd('/srv/app')).toBe('/srv/app');
    expect(assertCwd('~/proj')).toBe('~/proj');
    expect(assertCwd(`/${'a'.repeat(4095)}`)).toHaveLength(4096);
  });

  it('rejects relative paths, empty, NUL/newline, and over-length', () => {
    const bad = ['rel/path', '', '/a\nb', '/a\rb', '/a\u0000b', `/${'a'.repeat(4096)}`];
    for (const v of bad) {
      expect(codeOf(() => assertCwd(v))).toBe('invalid_cwd');
    }
  });
});

describe('assertTarget', () => {
  it('returns destination without port and keeps jumps', () => {
    const jumps = [{ host: 'bastion', port: 22 }];
    const t = assertTarget({ user: 'deploy', host: 'web.example', port: 2222, jumps });
    expect(t).toEqual({ destination: 'deploy@web.example', jumps });
    expect(t.destination).not.toContain('2222');
  });

  it('validates user, host, port and each jump', () => {
    const base = { user: 'deploy', host: 'web.example', port: 22, jumps: [] };
    expect(codeOf(() => assertTarget({ ...base, user: '-x' }))).toBe('invalid_user');
    expect(codeOf(() => assertTarget({ ...base, host: '-oProxyCommand=x' }))).toBe('invalid_host');
    expect(codeOf(() => assertTarget({ ...base, port: 0 }))).toBe('invalid_port');
    expect(codeOf(() => assertTarget({ ...base, jumps: [{ host: 'a b' }] }))).toBe('invalid_host');
    expect(codeOf(() => assertTarget({ ...base, jumps: [{ host: 'j', user: 'a@b' }] }))).toBe('invalid_user');
    expect(codeOf(() => assertTarget({ ...base, jumps: [{ host: 'j', port: 70000 }] }))).toBe('invalid_port');
  });

  it('rejects more than three jumps', () => {
    const jumps = [{ host: 'a' }, { host: 'b' }, { host: 'c' }, { host: 'd' }];
    expect(codeOf(() => assertTarget({ user: 'u', host: 'h', port: 22, jumps }))).toBe('invalid_jump');
  });
});

describe('selectJumpSpec', () => {
  it('returns no jumps when proxyJump is undefined', () => {
    expect(selectJumpSpec(undefined)).toEqual([]);
  });

  it('parses a bare host with default port 22 and no user', () => {
    expect(selectJumpSpec('bastion')).toEqual([{ host: 'bastion', port: 22 }]);
  });

  it('applies defaults for user and port when missing', () => {
    expect(selectJumpSpec('bastion', { user: 'jump', port: 2200 })).toEqual([
      { user: 'jump', host: 'bastion', port: 2200 },
    ]);
  });

  it('parses user@host:port', () => {
    expect(selectJumpSpec('user@host:2222')).toEqual([{ user: 'user', host: 'host', port: 2222 }]);
  });

  it('parses bracketed IPv6 with and without port', () => {
    expect(selectJumpSpec('[::1]:22')).toEqual([{ host: '::1', port: 22 }]);
    expect(selectJumpSpec('u@[2001:db8::1]')).toEqual([{ user: 'u', host: '2001:db8::1', port: 22 }]);
  });

  it('accepts exactly three hops', () => {
    expect(selectJumpSpec('a,b,c')).toHaveLength(3);
  });

  it('rejects more than three hops', () => {
    expect(codeOf(() => selectJumpSpec('a,b,c,d'))).toBe('invalid_jump');
  });

  it('rejects empty elements and empty string', () => {
    for (const bad of ['', 'a,,b', 'a,', ',a']) {
      expect(codeOf(() => selectJumpSpec(bad))).toBe('invalid_jump');
    }
  });

  it('rejects illegal characters, option-like hosts, bad ports and unbracketed IPv6', () => {
    for (const bad of ['a b', '-oProxyCommand=x', 'host:0', 'host:70000', 'host:abc', '::1', 'us er@h', 'u@[::1']) {
      expect(codeOf(() => selectJumpSpec(bad))).toBe('invalid_jump');
    }
  });
});

describe('resolveIdentityFile', () => {
  it('returns undefined for undefined', () => {
    expect(resolveIdentityFile(undefined, KH)).toBeUndefined();
  });

  it('resolves relative paths against baseDir', () => {
    const base = path.resolve('cfg-base');
    expect(resolveIdentityFile('keys/id', base)).toBe(path.resolve(base, 'keys', 'id'));
  });

  it('expands "~", "~/..." and "~\\..." to the current user home directory', () => {
    const home = os.homedir();
    expect(resolveIdentityFile('~/.ssh/id_ed25519', KH)).toBe(
      path.resolve(home, '.ssh', 'id_ed25519'),
    );
    expect(resolveIdentityFile('~/x', KH)).toBe(path.resolve(home, 'x'));
    expect(resolveIdentityFile('~\\x', KH)).toBe(path.resolve(home, 'x'));
    expect(resolveIdentityFile('~', KH)).toBe(path.resolve(home));
  });

  it('rejects ~other and NUL bytes with ConfigError schema', () => {
    for (const bad of ['~other/x', 'a\u0000b', '']) {
      try {
        resolveIdentityFile(bad, KH);
        expect.unreachable();
      } catch (e) {
        expect(e).toBeInstanceOf(ConfigError);
        expect((e as ConfigError).code).toBe('schema');
      }
    }
  });
});

describe('effectiveHost', () => {
  const baseDir = path.resolve('cfg-base');
  const cfg = makeConfig(baseDir);

  it('merges defaults for hosts that do not override them', () => {
    const web = effectiveHost(cfg, 'web');
    expect(web).toMatchObject({
      alias: 'web',
      host: 'web.example',
      user: 'deploy',
      port: 2222,
      cwd: '/home/x',
      timeouts: { connectMs: 5000, commandMs: 60000, checkMs: 10000 },
      maxOutputBytes: 4096,
      sudo: { mode: 'off', allow: ['systemctl'], deny: [] },
    });
    expect(web.identityFile).toBeUndefined();
    expect(web.proxyJump).toBeUndefined();
  });

  it('applies host-level overrides and resolves identityFile against baseDir', () => {
    const db = effectiveHost(cfg, 'db');
    expect(db.port).toBe(22);
    expect(db.cwd).toBe('/var');
    expect(db.identityFile).toBe(path.resolve(baseDir, 'keys', 'db'));
    expect(db.proxyJump).toBe('bastion');
  });

  it('does not share mutable defaults with the config', () => {
    const web = effectiveHost(cfg, 'web');
    web.sudo.allow.push('rm');
    web.timeouts.connectMs = 1;
    expect(cfg.defaults.sudo.allow).toEqual(['systemctl']);
    expect(cfg.defaults.timeouts.connectMs).toBe(5000);
  });

  it('treats an empty proxy_jump as undefined (no throw, no -J)', () => {
    const cfg2 = makeConfig(baseDir);
    cfg2.hosts['emptyjump'] = { host: 'empty.example', user: 'u', proxyJump: '' };
    const eff = effectiveHost(cfg2, 'emptyjump');
    expect(eff.proxyJump).toBeUndefined();
    const { argv } = buildSshArgv({ knownHostsFile: KH, mode: 'strict', host: eff });
    expect(argv).not.toContain('-J');
  });

  it('throws unknown_alias for missing hosts, including prototype keys', () => {
    expect(codeOf(() => effectiveHost(cfg, 'nope'))).toBe('unknown_alias');
    expect(codeOf(() => effectiveHost(cfg, 'constructor'))).toBe('unknown_alias');
  });

  it('validates the alias first', () => {
    expect(codeOf(() => effectiveHost(cfg, 'Bad Alias'))).toBe('invalid_alias');
  });

  describe('proxyJump normalization', () => {
    function jumpConfig(): RemoteConfig {
      const base = makeConfig(path.resolve('cfg-base'));
      return {
        ...base,
        defaults: { ...base.defaults, port: 22 },
        hosts: {
          bastion: { host: '10.0.0.1', user: 'admin', port: 2222 },
          inner: { host: '10.0.0.2', user: 'hop' },
          mid: { host: '10.0.0.9', user: 'mu', proxyJump: 'bastion' },
          db: { host: 'db.internal', user: 'ops', proxyJump: 'bastion' },
          literal: { host: 'lit', user: 'u', proxyJump: 'jump.example.com' },
          chain: { host: 'chain', user: 'u', proxyJump: 'bastion,inner' },
          nested: { host: 'nested', user: 'u', proxyJump: 'mid' },
          self: { host: 'selfhost', user: 'u', proxyJump: 'self' },
          a: { host: 'ahost', user: 'u', proxyJump: 'b' },
          b: { host: 'bhost', user: 'u', proxyJump: 'a' },
        },
      };
    }
    const jcfg = jumpConfig();

    it('resolves an alias jump to user@host:port', () => {
      expect(effectiveHost(jcfg, 'db').proxyJump).toBe('admin@10.0.0.1:2222');
    });

    it('keeps literal jump hosts unchanged', () => {
      expect(effectiveHost(jcfg, 'literal').proxyJump).toBe('jump.example.com');
    });

    it('resolves a two-hop chain and omits port 22', () => {
      expect(effectiveHost(jcfg, 'chain').proxyJump).toBe('admin@10.0.0.1:2222,hop@10.0.0.2');
    });

    it('expands a jump alias that has its own proxy_jump (outermost first)', () => {
      expect(effectiveHost(jcfg, 'nested').proxyJump).toBe('admin@10.0.0.1:2222,mu@10.0.0.9');
    });

    it('rejects self-references and cycles with invalid_jump', () => {
      expect(codeOf(() => effectiveHost(jcfg, 'self'))).toBe('invalid_jump');
      expect(codeOf(() => effectiveHost(jcfg, 'a'))).toBe('invalid_jump');
      expect(codeOf(() => effectiveHost(jcfg, 'b'))).toBe('invalid_jump');
    });

    it('leaves proxyJump undefined when not configured', () => {
      expect(effectiveHost(jcfg, 'bastion').proxyJump).toBeUndefined();
    });
  });
});

describe('describeHost', () => {
  it('omits the via part when there is no jump host', () => {
    expect(describeHost(makeHost())).toBe('web (deploy@web.example:2222)');
  });

  it('shows port 22 explicitly and lists jumps', () => {
    const db = makeHost({ alias: 'db' as Alias, host: 'db', user: 'ops', port: 22, proxyJump: 'a,b' });
    expect(describeHost(db)).toBe('db (ops@db:22, via a,b)');
  });
});

describe('baseSshOptions', () => {
  it('returns the hardening options in a fixed order', () => {
    expect(baseSshOptions({ knownHostsFile: KH, connectMs: 5000, mode: 'strict' })).toEqual([
      '-o', 'BatchMode=yes',
      '-o', 'ConnectTimeout=5',
      '-o', 'ServerAliveInterval=15',
      '-o', 'ServerAliveCountMax=3',
      '-o', 'StrictHostKeyChecking=yes',
      '-o', `UserKnownHostsFile=${KH}`,
      '-o', 'GlobalKnownHostsFile=none',
      '-o', 'CheckHostIP=no',
      '-o', 'UpdateHostKeys=no',
      '-o', 'HashKnownHosts=no',
      '-o', 'ControlMaster=no',
      '-o', 'ControlPath=none',
      '-T',
    ]);
  });

  it('rounds ConnectTimeout up and maps accept-new', () => {
    const opts = baseSshOptions({ knownHostsFile: KH, connectMs: 1500, mode: 'accept-new' });
    expect(opts).toContain('ConnectTimeout=2');
    expect(opts).toContain('StrictHostKeyChecking=accept-new');
  });

  it('requires an absolute known_hosts path', () => {
    expect(() => baseSshOptions({ knownHostsFile: 'relative/kh', connectMs: 5000, mode: 'strict' })).toThrow();
  });
});

describe('buildSshArgv', () => {
  const base = { knownHostsFile: KH, mode: 'strict' as const };

  it('starts with the hardening options and omits the executable', () => {
    const { argv } = buildSshArgv({ ...base, host: makeHost() });
    const hardening = baseSshOptions({ knownHostsFile: KH, connectMs: 5000, mode: 'strict' });
    expect(argv.slice(0, hardening.length)).toEqual([...hardening]);
    expect(argv).not.toContain('ssh');
  });

  it('places -p before "--" and the destination after it', () => {
    const { argv } = buildSshArgv({ ...base, host: makeHost() });
    const p = argv.indexOf('-p');
    const sep = argv.indexOf('--');
    expect(argv[p + 1]).toBe('2222');
    expect(p).toBeLessThan(sep);
    expect(argv[sep + 1]).toBe('deploy@web.example');
    expect(argv).toHaveLength(sep + 2);
  });

  it('does not emit -p when the port is 22', () => {
    const { argv } = buildSshArgv({ ...base, host: makeHost({ port: 22 }) });
    expect(argv).not.toContain('-p');
  });

  it('inserts extra options before "--"', () => {
    const { argv } = buildSshArgv({ ...base, host: makeHost(), extra: ['-J', 'bastion'] });
    const sep = argv.indexOf('--');
    expect(argv.slice(sep - 2, sep)).toEqual(['-J', 'bastion']);
  });

  it('does not emit -i or -J when the host has neither', () => {
    const { argv } = buildSshArgv({ ...base, host: makeHost() });
    expect(argv).not.toContain('-i');
    expect(argv).not.toContain('-J');
  });

  it('emits -i <path> after -p and -J <value> before "--"', () => {
    const host = makeHost({ identityFile: '/home/deploy/.ssh/id_ed25519', proxyJump: 'bastion' });
    const { argv, display } = buildSshArgv({ ...base, host });
    const sep = argv.indexOf('--');
    const p = argv.indexOf('-p');
    const i = argv.indexOf('-i');
    const j = argv.indexOf('-J');
    expect(p).toBeGreaterThan(-1);
    expect(argv[i + 1]).toBe('/home/deploy/.ssh/id_ed25519');
    expect(argv[j + 1]).toBe('bastion');
    expect(i).toBeGreaterThan(p);
    expect(j).toBeGreaterThan(i);
    expect(j).toBeLessThan(sep);
    expect(display).toContain('/home/deploy/.ssh/id_ed25519');
    expect(display).toContain('bastion');
  });

  it('omits -J for an empty proxyJump', () => {
    const { argv } = buildSshArgv({ ...base, host: makeHost({ proxyJump: '' }) });
    expect(argv).not.toContain('-J');
  });

  it('omits -i for an empty identityFile', () => {
    const { argv, display } = buildSshArgv({ ...base, host: makeHost({ identityFile: '' }) });
    expect(argv).not.toContain('-i');
    expect(display).not.toContain('-i ');
  });

  it('keeps remoteCommand as one argv element', () => {
    const cmd = "ls -la '/tmp/a b'; echo $HOME";
    const { argv } = buildSshArgv({ ...base, host: makeHost(), remoteCommand: cmd });
    expect(argv[argv.length - 1]).toBe(cmd);
    expect(argv[argv.length - 2]).toBe('deploy@web.example');
  });

  it('includes the strict or accept-new mode in the display', () => {
    expect(buildSshArgv({ ...base, host: makeHost() }).display).toContain('StrictHostKeyChecking=yes');
    expect(buildSshArgv({ ...base, mode: 'accept-new', host: makeHost() }).display).toContain(
      'StrictHostKeyChecking=accept-new',
    );
  });

  it('display starts with "ssh " and quotes elements that need it', () => {
    const { display } = buildSshArgv({ ...base, host: makeHost(), remoteCommand: "echo 'hi there'" });
    expect(display.startsWith('ssh -o BatchMode=yes ')).toBe(true);
    expect(display.endsWith(`'echo '\\''hi there'\\'''`)).toBe(true);
  });

  it('quotes an empty remoteCommand', () => {
    const { display } = buildSshArgv({ ...base, host: makeHost(), remoteCommand: '' });
    expect(display.endsWith(" ''")).toBe(true);
  });

  it('refuses a destination that starts with "-"', () => {
    expect(() => buildSshArgv({ ...base, host: makeHost({ user: '-x' }) })).toThrow();
  });

  it('refuses a NUL byte in remoteCommand', () => {
    expect(() => buildSshArgv({ ...base, host: makeHost(), remoteCommand: 'a\u0000b' })).toThrow();
  });
});

describe('buildSshGArgv', () => {
  it('returns ["-G", destination] without the port', () => {
    expect(buildSshGArgv(makeHost())).toEqual(['-G', 'deploy@web.example']);
  });
});

describe('assertArgvSafe', () => {
  it('rejects empty argv', () => {
    expect(() => assertArgvSafe([])).toThrow();
  });

  it('rejects NUL bytes', () => {
    expect(() => assertArgvSafe(['ok', 'a\u0000b'])).toThrow();
  });

  it('rejects a "-" option directly after "--"', () => {
    expect(() => assertArgvSafe(['--', '-x'])).toThrow();
    expect(() => assertArgvSafe(['a', '--', '-x', 'y'])).toThrow();
  });

  it('accepts a normal destination after "--" and a trailing "--"', () => {
    expect(() => assertArgvSafe(['-p', '1', '--', 'u@h', 'ls'])).not.toThrow();
    expect(() => assertArgvSafe(['-o', '--'])).not.toThrow();
  });
});

describe('checkTrustState', () => {
  const alias = 'web' as Alias;

  function keyMaterial() {
    const { publicKey } = generateKeyPairSync('ed25519');
    const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    const algo = Buffer.from('ssh-ed25519');
    const u32 = (n: number) => {
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

  function pin(fingerprint: string, keyBlob: string): PinnedHostKey {
    return {
      algorithm: 'ssh-ed25519',
      keyBlob,
      fingerprint,
      firstSeenAt: '2026-10-01T00:00:00Z',
      lastVerifiedAt: '2026-10-01T00:00:00Z',
    };
  }

  function entry(hosts: string[], keyBlob: string, marker: KnownHostEntry['marker'] = null): KnownHostEntry {
    return { marker, hosts, algorithm: 'ssh-ed25519', keyBlob, raw: '', line: 1 };
  }

  const keyA = keyMaterial();
  const keyB = keyMaterial();
  const host = makeHost({ host: 'web.example', port: 2222 });

  it('returns not_registered when the alias has no pinned key', () => {
    const r = checkTrustState({
      alias,
      host,
      registry: { version: 1, hosts: {} },
      knownHosts: [entry(['[web.example]:2222'], keyA.keyBlob)],
    });
    expect(r).toEqual({ ok: false, fact: { reason: 'not_registered' } });
  });

  it('returns known_hosts_missing when no matching line exists', () => {
    const registry: TrustRegistry = { version: 1, hosts: { web: pin(keyA.fingerprint, keyA.keyBlob) } };
    expect(checkTrustState({ alias, host, registry, knownHosts: [] })).toEqual({
      ok: false,
      fact: { reason: 'known_hosts_missing' },
    });
    expect(
      checkTrustState({
        alias,
        host,
        registry,
        knownHosts: [entry(['other.example'], keyA.keyBlob)],
      }),
    ).toEqual({ ok: false, fact: { reason: 'known_hosts_missing' } });
  });

  it('returns fingerprint_mismatch when only a different key is known', () => {
    const registry: TrustRegistry = { version: 1, hosts: { web: pin(keyA.fingerprint, keyA.keyBlob) } };
    expect(
      checkTrustState({
        alias,
        host,
        registry,
        knownHosts: [entry(['[web.example]:2222'], keyB.keyBlob)],
      }),
    ).toEqual({ ok: false, fact: { reason: 'fingerprint_mismatch' } });
  });

  it('returns ok with the pinned record when a matching line has the pinned fingerprint', () => {
    const pinned = pin(keyA.fingerprint, keyA.keyBlob);
    const r = checkTrustState({
      alias,
      host,
      registry: { version: 1, hosts: { web: pinned } },
      knownHosts: [entry(['[web.example]:2222'], keyB.keyBlob), entry(['[web.example]:2222'], keyA.keyBlob)],
    });
    expect(r).toEqual({ ok: true, pinned });
  });

  it('matches a bare host for port 22 and is case-insensitive on names', () => {
    const pinned = pin(keyA.fingerprint, keyA.keyBlob);
    const r = checkTrustState({
      alias,
      host: makeHost({ host: 'web.example', port: 22 }),
      registry: { version: 1, hosts: { web: pinned } },
      knownHosts: [entry(['Web.Example'], keyA.keyBlob)],
    });
    expect(r.ok).toBe(true);
  });

  it('does not match a bare host for a non-22 port', () => {
    const registry: TrustRegistry = { version: 1, hosts: { web: pin(keyA.fingerprint, keyA.keyBlob) } };
    expect(
      checkTrustState({
        alias,
        host,
        registry,
        knownHosts: [entry(['web.example'], keyA.keyBlob)],
      }),
    ).toEqual({ ok: false, fact: { reason: 'known_hosts_missing' } });
  });

  it('ignores @revoked lines even when they carry the pinned key', () => {
    const registry: TrustRegistry = { version: 1, hosts: { web: pin(keyA.fingerprint, keyA.keyBlob) } };
    expect(
      checkTrustState({
        alias,
        host,
        registry,
        knownHosts: [entry(['[web.example]:2222'], keyA.keyBlob, '@revoked')],
      }),
    ).toEqual({ ok: false, fact: { reason: 'known_hosts_missing' } });
  });

  it('does not throw on malformed input and fails closed', () => {
    const registry: TrustRegistry = { version: 1, hosts: { web: pin(keyA.fingerprint, keyA.keyBlob) } };
    const bad = { ...entry(['[web.example]:2222'], keyA.keyBlob), keyBlob: undefined as unknown as string };
    expect(() => checkTrustState({ alias, host, registry, knownHosts: [bad] })).not.toThrow();
    expect(checkTrustState({ alias, host, registry, knownHosts: [bad] }).ok).toBe(false);
  });
});

