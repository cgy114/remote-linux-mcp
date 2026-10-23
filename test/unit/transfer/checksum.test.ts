import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  hashLocalFile,
  parseSha256,
  remoteHashCommand,
  remoteHashSnippet,
} from '../../../src/transfer/checksum.js';

const ABC_SHA = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

describe('checksum', () => {
  let root: string;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-sha-'));
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  it('hashes a local file as a stream', async () => {
    const file = path.join(root, 'abc.txt');
    await fs.writeFile(file, 'abc');
    await expect(hashLocalFile(file)).resolves.toEqual({ sha256: ABC_SHA, bytes: 3 });
  });

  it('hashes files larger than one chunk', async () => {
    const file = path.join(root, 'large.bin');
    const data = Buffer.alloc(200_000, 7);
    await fs.writeFile(file, data);
    const result = await hashLocalFile(file);
    expect(result.bytes).toBe(data.length);
    expect(result.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('builds a fallback remote hash snippet', () => {
    const snippet = remoteHashSnippet('~/a b');
    expect(snippet).toContain('sha256sum');
    expect(snippet).toContain('shasum -a 256');
    expect(snippet).toContain('openssl dgst -sha256');
    expect(snippet).toContain(`"$HOME"'/a b'`);
    expect(snippet).toContain('exit 127');
  });

  it('accepts an already rendered path expression', () => {
    expect(remoteHashCommand('"$f"')).toContain('sha256sum -- "$f"');
  });

  it('parses sha256 from sha256sum/shasum/openssl output', () => {
    expect(parseSha256(`${ABC_SHA}  file.txt`)).toBe(ABC_SHA);
    expect(parseSha256(`SHA256 (file.txt) = ${ABC_SHA.toUpperCase()}`)).toBe(ABC_SHA);
    expect(parseSha256(`(stdin)= ${ABC_SHA}`)).toBe(ABC_SHA);
    expect(parseSha256('no hash here')).toBeUndefined();
    expect(parseSha256(`${ABC_SHA}0`)).toBeUndefined();
  });
});
