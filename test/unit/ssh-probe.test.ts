import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { classify } from '../../src/errors/classify.js';
import type { Alias, EffectiveHost, Logger, MCPPaths } from '../../src/types.js';
import { buildChildEnv } from '../../src/ssh/env.js';
import { resolveToolBinary } from '../../src/ssh/binary.js';
import {
  buildCheckCommand,
  parseCheckOutput,
  parseKnownHosts,
  parseSshG,
  probeHostKey,
  runHostCheckProbe,
  runSshG,
  verifyTrustedConnection,
} from '../../src/ssh/probe.js';

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

/** 一个肯定不存在的 ssh 可执行路径，用于触发 spawnError。 */
const MISSING_SSH = path.join(os.tmpdir(), 'definitely-missing-ssh-for-test.exe');

// ---------- buildCheckCommand ----------

describe('buildCheckCommand', () => {
  it('contains uname and every sshd version attempt in order', () => {
    const cmd = buildCheckCommand({ markerBegin: 'BEG', markerEnd: 'END' });
    expect(cmd).toContain('uname -srm');
    const iSshd = cmd.indexOf('sshd -V 2>&1');
    const iUsr = cmd.indexOf('/usr/sbin/sshd -V 2>&1');
    const iDpkg = cmd.indexOf('dpkg-query -W');
    const iSsh = cmd.indexOf('ssh -V 2>&1');
    expect(iSshd).toBeGreaterThan(-1);
    expect(iUsr).toBeGreaterThan(iSshd);
    expect(iDpkg).toBeGreaterThan(iUsr);
    expect(iSsh).toBeGreaterThan(iDpkg);
  });

  it('single-quote escapes markers', () => {
    const cmd = buildCheckCommand({ markerBegin: "a'b", markerEnd: 'END' });
    expect(cmd).toContain(`printf '%s\\n' 'a'\\''b'`);
  });

  it('never contains a newline', () => {
    const cmd = buildCheckCommand({ markerBegin: 'BEG', markerEnd: 'END' });
    expect(cmd).not.toMatch(/[\r\n]/);
  });

  it('rejects markers containing a newline', () => {
    expect(() => buildCheckCommand({ markerBegin: 'a\nb', markerEnd: 'END' })).toThrow();
  });
});

// ---------- parseCheckOutput ----------

describe('parseCheckOutput', () => {
  it('parses uname and OpenSSH version between markers', () => {
    const out = [
      'noise before',
      'BEGIN-X',
      'Linux 6.8.0-generic x86_64',
      'OpenSSH_9.6p1, OpenSSL 3.0.13 30 Jan 2024',
      'END-X',
      'noise after',
    ].join('\n');
    // 标记使用固定前缀，这里模拟真实前缀
    const real = [
      'banner',
      'REMOTE_MCP_CHECK_BEGIN_abc',
      'Linux 6.8.0-generic x86_64',
      'OpenSSH_9.6p1, OpenSSL 3.0.13 30 Jan 2024',
      'REMOTE_MCP_CHECK_END_abc',
      'trailing',
    ].join('\n');
    expect(parseCheckOutput(real)).toEqual({
      uname: 'Linux 6.8.0-generic x86_64',
      sshdVersion: '9.6',
    });
    expect(() => parseCheckOutput(out)).toThrow();
  });

  it('falls back to a dpkg version number', () => {
    const out = [
      'REMOTE_MCP_CHECK_BEGIN_n',
      'Linux 5.15.0 x86_64',
      '1:9.6p1-3ubuntu13',
      'REMOTE_MCP_CHECK_END_n',
    ].join('\n');
    expect(parseCheckOutput(out)).toEqual({ uname: 'Linux 5.15.0 x86_64', sshdVersion: '9.6' });
  });

  it('throws Internal invalid_output when markers are missing', () => {
    let caught: (Error & { code?: string; kind?: string }) | undefined;
    try {
      parseCheckOutput('Linux x86_64\nOpenSSH_9.6p1\n');
    } catch (err) {
      caught = err as Error & { code?: string; kind?: string };
    }
    expect(caught).toBeInstanceOf(Error);
    expect(caught?.code).toBe('invalid_output');
    expect(caught?.kind).toBe('Internal');
  });

  it('throws when only the begin marker is present', () => {
    expect(() => parseCheckOutput('REMOTE_MCP_CHECK_BEGIN_x\nLinux\n')).toThrow();
  });
});

// ---------- parseSshG ----------

describe('parseSshG', () => {
  it('lowercases keys, merges repeated keys, and ignores blank lines', () => {
    const out = [
      'Hostname example.com',
      '',
      'identityfile ~/.ssh/id_a',
      'IdentityFile ~/.ssh/id_b',
      '   ',
      'port 22',
    ].join('\n');
    expect(parseSshG(out)).toEqual({
      hostname: ['example.com'],
      identityfile: ['~/.ssh/id_a', '~/.ssh/id_b'],
      port: ['22'],
    });
  });

  it('returns an empty map for empty input', () => {
    expect(parseSshG('')).toEqual({});
  });
});

describe('runSshG', () => {
  it('resolves the effective config for localhost (skipped if ssh is unavailable)', async () => {
    let available = true;
    try {
      await resolveToolBinary('ssh');
    } catch {
      available = false;
    }
    if (!available) {
      console.warn('ssh not available; skipping runSshG localhost test');
      return;
    }
    const map = await runSshG({
      host: makeHost({ host: 'localhost', user: 'tester' }),
      env: buildChildEnv(),
      timeoutMs: 10_000,
    });
    expect(map['hostname']).toBeDefined();
  });

  it('throws Internal ssh_g_failed when the ssh path is missing', async () => {
    await expect(
      runSshG({ host: makeHost(), env: buildChildEnv(), timeoutMs: 2000, sshPath: MISSING_SSH }),
    ).rejects.toMatchObject({ code: 'ssh_g_failed', kind: 'Internal' });
  });
});

// ---------- parseKnownHosts / probeHostKey ----------

describe('parseKnownHosts', () => {
  it('skips blank, comment and @-marker lines and parses entries', () => {
    const text = [
      '# comment',
      '',
      '@cert-authority *.example.com ssh-ed25519 AAAACERT',
      'example.com,10.0.0.1 ssh-ed25519 AAAAKEY1',
      '[host.example]:2222 ecdsa-sha2-nistp256 AAAAKEY2',
    ].join('\n');
    const entries = parseKnownHosts(text);
    expect(entries).toHaveLength(2);
    expect(entries[0]).toEqual({
      marker: null,
      hosts: ['example.com', '10.0.0.1'],
      algorithm: 'ssh-ed25519',
      keyBlob: 'AAAAKEY1',
      raw: 'example.com,10.0.0.1 ssh-ed25519 AAAAKEY1',
      line: 4,
    });
    expect(entries[1]?.hosts).toEqual(['[host.example]:2222']);
    expect(entries[1]?.line).toBe(5);
  });

  it('ignores malformed lines with fewer than three fields', () => {
    expect(parseKnownHosts('onlyhost ssh-ed25519\n')).toEqual([]);
  });
});

describe('probeHostKey', () => {
  it('fails with a probe-phase fact when the ssh binary is missing', async () => {
    const r = await probeHostKey({
      host: makeHost(),
      timeoutMs: 2000,
      log: silentLog,
      sshPath: MISSING_SSH,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.fact.phase).toBe('probe');
    expect(r.fact.spawnError).toBeDefined();
    expect(classify(r.fact)).toBe('Internal');
  });

  // 「条目数 !== 1 → probe_ambiguous」以及成功路径需要真实或伪造的 ssh 写入 known_hosts，
  // 当前无注入点，留待集成测试覆盖；此处只覆盖解析层。
});

// ---------- verifyTrustedConnection / runHostCheckProbe ----------

describe('verifyTrustedConnection', () => {
  it('returns a classified fact instead of throwing for a missing ssh path', async () => {
    const r = await verifyTrustedConnection({
      host: makeHost(),
      paths: makePaths(),
      log: silentLog,
      sshPath: MISSING_SSH,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.fact.phase).toBe('verify');
    expect(r.fact.spawnError).toBeDefined();
    expect(classify(r.fact)).toBe('Internal');
  });
});

describe('runHostCheckProbe', () => {
  it('returns a RunResult with spawnError for a missing ssh path and does not throw', async () => {
    const run = await runHostCheckProbe({
      host: makeHost(),
      paths: makePaths(),
      timeoutMs: 2000,
      maxOutputBytes: 65536,
      log: silentLog,
      sshPath: MISSING_SSH,
    });
    expect(run.spawnError).toBeDefined();
    expect(run.exitCode).toBeNull();
  });
});
