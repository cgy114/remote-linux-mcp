import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ConfigError } from '../../src/errors/classes.js';
import { resolveToolBinary } from '../../src/ssh/binary.js';
import { fingerprintKey } from '../../src/util/fingerprint.js';
import {
  findHostKeyEntries,
  formatKnownHostsEntry,
  parseKnownHostsLine,
  queryUserKnownHosts,
  readKnownHosts,
  writeKnownHostsEntry,
} from '../../src/trust/known-hosts.js';

const BLOB_A = Buffer.from('key-blob-A-bytes').toString('base64');
const BLOB_B = Buffer.from('key-blob-B-bytes').toString('base64');
const BLOB_C = Buffer.from('key-blob-C-bytes').toString('base64');

describe('parseKnownHostsLine', () => {
  it('returns null for empty lines and comments', () => {
    expect(parseKnownHostsLine('', 1)).toBeNull();
    expect(parseKnownHostsLine('   ', 2)).toBeNull();
    expect(parseKnownHostsLine('# comment', 3)).toBeNull();
  });

  it('parses a plain entry with lineNo and raw', () => {
    const e = parseKnownHostsLine(`example.com ssh-ed25519 ${BLOB_A}`, 7);
    expect(e).toEqual({
      marker: null,
      hosts: ['example.com'],
      algorithm: 'ssh-ed25519',
      keyBlob: BLOB_A,
      raw: `example.com ssh-ed25519 ${BLOB_A}`,
      line: 7,
    });
  });

  it('splits hosts on commas, not whitespace', () => {
    const e = parseKnownHostsLine(`a.example,[b.example]:2222 ssh-ed25519 ${BLOB_A}`, 1);
    expect(e?.hosts).toEqual(['a.example', '[b.example]:2222']);
  });

  it('recognises @cert-authority and @revoked markers', () => {
    expect(parseKnownHostsLine(`@revoked host.x ssh-ed25519 ${BLOB_A}`, 1)?.marker).toBe('@revoked');
    expect(parseKnownHostsLine(`@cert-authority host.x ssh-ed25519 ${BLOB_A}`, 1)?.marker).toBe(
      '@cert-authority',
    );
  });

  it('keeps hashed hostnames as a single unresolved name', () => {
    const hashed = '|1|c2FsdA==|aGFzaA==';
    const e = parseKnownHostsLine(`${hashed} ssh-ed25519 ${BLOB_A}`, 1);
    expect(e?.hosts).toEqual([hashed]);
  });

  it('returns null (never throws) for invalid lines', () => {
    expect(parseKnownHostsLine('onlyhost', 1)).toBeNull();
    expect(parseKnownHostsLine(`host ssh-ed25519`, 1)).toBeNull();
    expect(parseKnownHostsLine(`@bogus host ssh-ed25519 ${BLOB_A}`, 1)).toBeNull();
    expect(parseKnownHostsLine(`host ssh-ed25519 !!!notbase64`, 1)).toBeNull();
  });
});

describe('findHostKeyEntries', () => {
  const entries = [
    parseKnownHostsLine(`bare.example ssh-ed25519 ${BLOB_A}`, 1)!,
    parseKnownHostsLine(`[alt.example]:2222 ssh-ed25519 ${BLOB_B}`, 2)!,
    parseKnownHostsLine(`@revoked bare.example ssh-ed25519 ${BLOB_C}`, 3)!,
    parseKnownHostsLine(`|1|c2FsdA==|aGFzaA== ssh-ed25519 ${BLOB_C}`, 4)!,
    parseKnownHostsLine(`[ported.example]:22 ssh-ed25519 ${BLOB_A}`, 5)!,
  ];

  it('port 22 matches bare host and [host]:22, case-insensitively', () => {
    expect(findHostKeyEntries(entries, 'BARE.example', 22).map((e) => e.line)).toEqual([1]);
    expect(findHostKeyEntries(entries, 'ported.example', 22).map((e) => e.line)).toEqual([5]);
  });

  it('non-22 port matches only [host]:port', () => {
    expect(findHostKeyEntries(entries, 'alt.example', 2222).map((e) => e.line)).toEqual([2]);
    expect(findHostKeyEntries(entries, 'bare.example', 2222)).toEqual([]);
    expect(findHostKeyEntries(entries, 'alt.example', 22)).toEqual([]);
  });

  it('skips @revoked and @cert-authority markers and hashed names', () => {
    const all = findHostKeyEntries(entries, 'bare.example', 22);
    expect(all.every((e) => e.marker === null)).toBe(true);
    expect(all.map((e) => e.line)).toEqual([1]);
  });
});

describe('formatKnownHostsEntry', () => {
  it('omits brackets for port 22', () => {
    expect(formatKnownHostsEntry({ host: 'h', port: 22, algorithm: 'ssh-ed25519', keyBlob: BLOB_A })).toBe(
      `h ssh-ed25519 ${BLOB_A}`,
    );
  });

  it('uses [host]:port otherwise, and round-trips through the parser', () => {
    const line = formatKnownHostsEntry({ host: 'h', port: 2200, algorithm: 'ssh-ed25519', keyBlob: BLOB_A });
    expect(line).toBe(`[h]:2200 ssh-ed25519 ${BLOB_A}`);
    const parsed = parseKnownHostsLine(line, 1);
    expect(parsed?.hosts).toEqual(['[h]:2200']);
    expect(parsed?.keyBlob).toBe(BLOB_A);
  });
});

describe('readKnownHosts', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-kh-'));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it('returns empty result for a missing file (tolerant or not)', async () => {
    const f = path.join(dir, 'nope');
    expect(await readKnownHosts(f)).toEqual({ entries: [], invalidLines: [] });
    expect(await readKnownHosts(f, { tolerant: false })).toEqual({ entries: [], invalidLines: [] });
  });

  it('collects invalid non-empty line numbers', async () => {
    const f = path.join(dir, 'kh');
    await fs.writeFile(f, `# c\n\nok.example ssh-ed25519 ${BLOB_A}\nbad line\n`, 'utf8');
    const res = await readKnownHosts(f);
    expect(res.entries.map((e) => e.line)).toEqual([3]);
    expect(res.invalidLines).toEqual([4]);
  });

  it('read error: tolerant -> empty with invalidLines [0]; strict -> ConfigError io', async () => {
    // 目录当作文件读取会触发 EISDIR
    expect(await readKnownHosts(dir)).toEqual({ entries: [], invalidLines: [0] });
    await expect(readKnownHosts(dir, { tolerant: false })).rejects.toMatchObject({
      name: 'ConfigError',
      code: 'io',
    });
    await expect(readKnownHosts(dir, { tolerant: false })).rejects.toBeInstanceOf(ConfigError);
  });
});

describe('writeKnownHostsEntry', () => {
  let dir: string;
  let file: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-kh-w-'));
    file = path.join(dir, 'sub', 'known_hosts');
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it('creates the file (and parent dir) when missing', async () => {
    await writeKnownHostsEntry({
      file,
      host: 'h.example',
      port: 22,
      algorithm: 'ssh-ed25519',
      keyBlob: BLOB_A,
      mode: 'replace-host',
    });
    expect(await fs.readFile(file, 'utf8')).toBe(`h.example ssh-ed25519 ${BLOB_A}\n`);
  });

  it('replaces bare and [host]:port forms for the same host/port, keeps other lines', async () => {
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(
      file,
      [
        '# my comment',
        `h.example ssh-ed25519 ${BLOB_B}`,
        `[h.example]:2200 ssh-ed25519 ${BLOB_B}`,
        `other.example ssh-ed25519 ${BLOB_C}`,
        `@revoked h.example ssh-ed25519 ${BLOB_C}`,
        '',
      ].join('\n'),
    );
    await writeKnownHostsEntry({
      file,
      host: 'h.example',
      port: 22,
      algorithm: 'ssh-ed25519',
      keyBlob: BLOB_A,
      mode: 'replace-host',
    });
    const text = await fs.readFile(file, 'utf8');
    expect(text).toBe(
      [
        '# my comment',
        `[h.example]:2200 ssh-ed25519 ${BLOB_B}`,
        `other.example ssh-ed25519 ${BLOB_C}`,
        `@revoked h.example ssh-ed25519 ${BLOB_C}`,
        `h.example ssh-ed25519 ${BLOB_A}`,
        '',
      ].join('\n'),
    );
  });

  it('removes only the matching name from a multi-host line', async () => {
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file, `h.example,keep.example ssh-ed25519 ${BLOB_B} comment\n`);
    await writeKnownHostsEntry({
      file,
      host: 'h.example',
      port: 22,
      algorithm: 'ssh-ed25519',
      keyBlob: BLOB_A,
      mode: 'replace-host',
    });
    const text = await fs.readFile(file, 'utf8');
    expect(text).toBe(`keep.example ssh-ed25519 ${BLOB_B} comment\nh.example ssh-ed25519 ${BLOB_A}\n`);
  });

  it('leaves no temp files behind after an atomic write', async () => {
    await writeKnownHostsEntry({
      file,
      host: 'h.example',
      port: 2222,
      algorithm: 'ssh-ed25519',
      keyBlob: BLOB_A,
      mode: 'replace-host',
    });
    const names = await fs.readdir(path.dirname(file));
    expect(names).toEqual(['known_hosts']);
    expect(await fs.readFile(file, 'utf8')).toContain(`[h.example]:2222 ssh-ed25519 ${BLOB_A}`);
  });
});

describe('queryUserKnownHosts', () => {
  let keygen: string | undefined;
  beforeEach(async () => {
    keygen = await resolveToolBinary('ssh-keygen').catch(() => undefined);
  });

  it('returns ok:false for a host that is certainly not present', async () => {
    if (keygen === undefined) return; // ssh-keygen 不可用时跳过
    const res = await queryUserKnownHosts({
      host: 'definitely-not-real.invalid',
      port: 22,
      sshKeygenPath: keygen,
      env: process.env,
    });
    expect(res.ok).toBe(false);
    expect(res.entries).toEqual([]);
  });

  it('finds the matching localhost entry in an explicit known_hosts file', async () => {
    if (keygen === undefined) return;
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-qkh-'));
    try {
      const file = path.join(dir, 'known_hosts');
      await fs.writeFile(file, `localhost ssh-ed25519 ${BLOB_A}\n`, 'utf8');
      const res = await queryUserKnownHosts({
        host: 'localhost',
        port: 22,
        file,
        sshKeygenPath: keygen,
        env: process.env,
      });
      expect(res.ok).toBe(true);
      expect(res.entries).toHaveLength(1);
      expect(res.entries[0]).toMatchObject({
        marker: null,
        hosts: ['localhost'],
        algorithm: 'ssh-ed25519',
        keyBlob: BLOB_A,
      });
      const expected =
        'SHA256:' +
        createHash('sha256').update(Buffer.from(BLOB_A, 'base64')).digest('base64').replace(/=+$/, '');
      expect(fingerprintKey(res.entries[0]!.keyBlob)).toBe(expected);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  });

  it('returns ok:false (no throw) when the binary path is bogus', async () => {
    const res = await queryUserKnownHosts({
      host: 'h',
      port: 22,
      sshKeygenPath: path.join(os.tmpdir(), 'no-such-ssh-keygen-binary'),
      env: process.env,
    });
    expect(res).toEqual({ ok: false, entries: [], raw: '' });
  });
});
