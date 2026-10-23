import { spawn } from 'node:child_process';
import { Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { buildChildEnv } from '../../src/ssh/env.js';
import {
  captureStream,
  killTree,
  runSsh,
  spawnCapture,
  truncateOutput,
  trackChild,
  waitForExit,
} from '../../src/ssh/runner.js';

const env = (): NodeJS.ProcessEnv => buildChildEnv({ base: { ProgramData: 'C:\\PD' } });

function streamOf(chunks: Buffer[]): NodeJS.ReadableStream {
  return Readable.from(chunks);
}

describe('truncateOutput', () => {
  it('returns text unchanged when within limit', () => {
    expect(truncateOutput('hello', 100)).toEqual({ text: 'hello', truncated: false });
  });

  it('keeps head and tail with a marker when over limit', () => {
    const r = truncateOutput('a'.repeat(100), 20);
    expect(r.truncated).toBe(true);
    expect(r.text).toMatch(/^a{10}\n\.\.\.\[truncated \d+ bytes\]\.\.\.\na{10}$/);
  });

  it('does not split multi-byte characters', () => {
    const text = '中文😀'.repeat(50);
    for (const max of [7, 10, 13, 20, 31]) {
      const r = truncateOutput(text, max);
      expect(r.text).not.toContain('\uFFFD');
    }
  });
});

describe('captureStream', () => {
  it('returns the full text when not over the limit', async () => {
    const r = await captureStream(streamOf([Buffer.from('ab'), Buffer.from('cd')]), 100);
    expect(r).toEqual({ text: 'abcd', truncated: false });
  });

  it('inserts a truncation marker under a small limit', async () => {
    const r = await captureStream(streamOf([Buffer.from('x'.repeat(500))]), 40);
    expect(r.truncated).toBe(true);
    expect(r.text).toContain('...[truncated');
  });

  it('does not corrupt Chinese and emoji across chunk boundaries', async () => {
    const full = Buffer.from('中文😀'.repeat(40), 'utf8');
    // split into 3-byte-ish chunks to force boundaries inside characters
    const chunks: Buffer[] = [];
    for (let i = 0; i < full.length; i += 5) chunks.push(full.subarray(i, i + 5));
    const r = await captureStream(streamOf(chunks), 30);
    expect(r.truncated).toBe(true);
    expect(r.text).not.toContain('\uFFFD');
  });

  it('returns unchanged multi-byte text exactly under the limit', async () => {
    const text = '中文😀测试';
    const r = await captureStream(streamOf([Buffer.from(text, 'utf8')]), 1000);
    expect(r).toEqual({ text, truncated: false });
  });
});

describe('waitForExit', () => {
  it('times out, calls onTimeout exactly once, and marks timedOut', async () => {
    const child = spawn(process.execPath, ['-e', 'setTimeout(()=>{},5000)'], {
      stdio: 'ignore',
      windowsHide: true,
    });
    let calls = 0;
    const r = await waitForExit(child, 200, () => {
      calls++;
      child.kill();
    });
    expect(r.timedOut).toBe(true);
    expect(calls).toBe(1);
  });

  it('reports the exit code on normal exit without timeout', async () => {
    const child = spawn(process.execPath, ['-e', 'process.exit(3)'], {
      stdio: 'ignore',
      windowsHide: true,
    });
    const r = await waitForExit(child, 5000, () => undefined);
    expect(r.exitCode).toBe(3);
    expect(r.timedOut).toBe(false);
  });
});

describe('spawnCapture', () => {
  it('captures stdout and exit code, and displayCommand includes the executable', async () => {
    const r = await spawnCapture({
      file: process.execPath,
      argv: ['-e', "process.stdout.write('hi there'); process.exit(7)"],
      env: env(),
      timeoutMs: 10_000,
      maxOutputBytes: 1024,
    });
    expect(r.exitCode).toBe(7);
    expect(r.stdout).toBe('hi there');
    expect(r.timedOut).toBe(false);
    expect(r.argv[0]).toBe(process.execPath);
    expect(r.displayCommand).toContain(process.execPath.includes(' ') ? `'${process.execPath}'` : process.execPath);
    expect(r.spawnError).toBeUndefined();
  });

  it('reports a spawn failure in spawnError instead of throwing', async () => {
    const r = await spawnCapture({
      file: 'C:\\definitely\\missing\\nope.exe',
      argv: [],
      env: env(),
      timeoutMs: 5000,
      maxOutputBytes: 1024,
    });
    expect(r.spawnError).toBeDefined();
    expect(r.exitCode).toBeNull();
  });
});

describe('runSsh', () => {
  it('runs ssh -V and yields version text on stderr or stdout', async () => {
    const r = await runSsh({
      argv: ['-V'],
      timeoutMs: 10_000,
      maxOutputBytes: 64 * 1024,
      env: env(),
      label: 'version',
    });
    expect(r.argv.length).toBe(2);
    expect(`${r.stderr}${r.stdout}`).toMatch(/OpenSSH/);
  });
});

describe('killTree', () => {
  it('kills a long-sleeping node child', async () => {
    const child = spawn(process.execPath, ['-e', 'setTimeout(()=>{},60000)'], {
      stdio: 'ignore',
      windowsHide: true,
    });
    const untrack = trackChild(child);
    const exited = new Promise<void>((resolve) => child.on('exit', () => resolve()));
    await killTree(child.pid!, 'taskkill');
    await Promise.race([
      exited,
      new Promise((_, rej) => setTimeout(() => rej(new Error('still alive')), 8000)),
    ]);
    untrack();
    expect(child.killed || child.exitCode !== null || child.signalCode !== null).toBe(true);
  });
});
