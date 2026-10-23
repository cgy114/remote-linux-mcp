import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { baseSshOptions, baseTransportOptions, buildSftpArgv } from '../../src/policy/argv.js';
import type { Alias, EffectiveHost } from '../../src/types.js';

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

describe('baseTransportOptions', () => {
  it('emits twelve -o pairs ending with ControlPath=none and no -T', () => {
    const opts = baseTransportOptions({ knownHostsFile: KH, connectMs: 5000, mode: 'strict' });
    expect(opts).toHaveLength(24);
    expect(opts.filter((v) => v === '-o')).toHaveLength(12);
    expect(opts.slice(-2)).toEqual(['-o', 'ControlPath=none']);
    expect(opts).not.toContain('-T');
  });

  it('baseSshOptions is exactly baseTransportOptions plus -T', () => {
    const transport = baseTransportOptions({ knownHostsFile: KH, connectMs: 1500, mode: 'accept-new' });
    const ssh = baseSshOptions({ knownHostsFile: KH, connectMs: 1500, mode: 'accept-new' });
    expect(ssh).toEqual([...transport, '-T']);
    expect(ssh).toContain('ConnectTimeout=2');
    expect(ssh).toContain('StrictHostKeyChecking=accept-new');
  });

  it('requires an absolute known_hosts path', () => {
    expect(() => baseTransportOptions({ knownHostsFile: 'relative/kh', connectMs: 5000, mode: 'strict' })).toThrow();
  });
});

describe('buildSftpArgv', () => {
  const base = { knownHostsFile: KH, mode: 'strict' as const };

  it('orders hardening, -P, -i, -J, extra, -q -b -, -- and destination without -T', () => {
    const host = makeHost({ identityFile: '/home/deploy/.ssh/id_ed25519', proxyJump: 'bastion' });
    const { argv, display } = buildSftpArgv({ ...base, host, extra: ['-l', '4096'] });
    const hardening = baseTransportOptions({ knownHostsFile: KH, connectMs: 5000, mode: 'strict' });
    expect(argv.slice(0, hardening.length)).toEqual([...hardening]);
    expect(argv).not.toContain('-T');

    const p = argv.indexOf('-P');
    const i = argv.indexOf('-i');
    const j = argv.indexOf('-J');
    const q = argv.indexOf('-q');
    const bat = argv.indexOf('-b');
    const sep = argv.indexOf('--');
    expect(argv[p + 1]).toBe('2222');
    expect(argv[i + 1]).toBe('/home/deploy/.ssh/id_ed25519');
    expect(argv[j + 1]).toBe('bastion');
    expect(i).toBeGreaterThan(p);
    expect(j).toBeGreaterThan(i);
    expect(q).toBeGreaterThan(j);
    expect(argv.slice(q, q + 3)).toEqual(['-q', '-b', '-']);
    expect(argv.slice(sep + 1)).toEqual(['deploy@web.example']);
    expect(argv[sep - 1]).toBe('-');
    expect(argv.slice(j + 2, q)).toEqual(['-l', '4096']);
    expect(bat).toBe(q + 1);
    expect(display.startsWith('sftp -o BatchMode=yes ')).toBe(true);
  });

  it('omits -P for port 22 and -i/-J when unset', () => {
    const { argv } = buildSftpArgv({ ...base, host: makeHost({ port: 22 }) });
    expect(argv).not.toContain('-P');
    expect(argv).not.toContain('-i');
    expect(argv).not.toContain('-J');
  });

  it.each(['-b', '-B', '-P', '-i', '-J', '-o', '-q', '-oProxyCommand=evil', '-i/tmp/key'])(
    'rejects the reserved extra %j',
    (item) => {
      expect(() => buildSftpArgv({ ...base, host: makeHost(), extra: [item] })).toThrow();
    },
  );

  it('rejects a NUL byte in extra', () => {
    expect(() => buildSftpArgv({ ...base, host: makeHost(), extra: ['a\u0000b'] })).toThrow();
  });
});
