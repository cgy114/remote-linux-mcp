import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { fingerprintKey, formatFingerprintDisplay } from '../../src/trust/fingerprint.js';
import { fingerprintKey as utilFingerprintKey } from '../../src/util/fingerprint.js';
import { resolveToolBinary } from '../../src/ssh/binary.js';

function independentFingerprint(b64: string): string {
  const digest = createHash('sha256').update(Buffer.from(b64, 'base64')).digest('base64');
  return 'SHA256:' + digest.replace(/=+$/, '');
}

describe('fingerprintKey', () => {
  const blob = Buffer.from('fixed-test-public-key-bytes-0123456789').toString('base64');

  it('matches an independently computed SHA256 with padding stripped', () => {
    expect(utilFingerprintKey(blob)).toBe(independentFingerprint(blob));
  });

  it('has no trailing "=" and carries the SHA256: prefix', () => {
    const fp = utilFingerprintKey(blob);
    expect(fp.startsWith('SHA256:')).toBe(true);
    expect(fp.endsWith('=')).toBe(false);
  });

  it('is re-exported by the trust module unchanged', () => {
    expect(fingerprintKey).toBe(utilFingerprintKey);
  });

  it('throws Internal invalid_key_blob for empty or non-base64 input', () => {
    for (const bad of ['', '!!!!', 'abc def', '====']) {
      let caught: (Error & { code?: string; kind?: string }) | undefined;
      try {
        utilFingerprintKey(bad);
      } catch (e) {
        caught = e as Error & { code?: string; kind?: string };
      }
      expect(caught, `input ${JSON.stringify(bad)}`).toBeInstanceOf(Error);
      expect(caught?.code).toBe('invalid_key_blob');
      expect(caught?.kind).toBe('Internal');
    }
  });
});

describe('fingerprintKey vs ssh-keygen -lf', () => {
  let keygen: string | undefined;
  let dir: string;

  beforeAll(async () => {
    keygen = await resolveToolBinary('ssh-keygen').catch(() => undefined);
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-fp-'));
  });

  afterAll(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it('agrees with OpenSSH for a freshly generated ed25519 key', async () => {
    if (keygen === undefined) return; // ssh-keygen 不可用时跳过
    const keyFile = path.join(dir, 'k_ed25519');
    execFileSync(keygen, ['-q', '-t', 'ed25519', '-N', '', '-f', keyFile]);
    const pub = (await fs.readFile(`${keyFile}.pub`, 'utf8')).trim();
    const [, blob] = pub.split(/\s+/);
    const out = execFileSync(keygen, ['-lf', `${keyFile}.pub`], { encoding: 'utf8' });
    const openssh = /(SHA256:\S+)/.exec(out)?.[1];
    expect(openssh).toBeDefined();
    expect(utilFingerprintKey(blob!)).toBe(openssh);
  });
});

describe('formatFingerprintDisplay', () => {
  it('renders fingerprint, host:port and uppercased algorithm', () => {
    expect(
      formatFingerprintDisplay({
        host: 'example.com',
        port: 2222,
        algorithm: 'ssh-ed25519',
        fingerprint: 'SHA256:abc',
      }),
    ).toBe('SHA256:abc  example.com:2222 (SSH-ED25519)');
  });
});
