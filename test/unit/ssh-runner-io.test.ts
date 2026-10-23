import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildChildEnv } from '../../src/ssh/env.js';
import { resolveToolBinary } from '../../src/ssh/binary.js';
import {
  captureStdoutAsBuffer,
  runSftp,
  spawnCapture,
} from '../../src/ssh/runner.js';

const env = (): NodeJS.ProcessEnv => buildChildEnv({ base: { ProgramData: 'C:\\PD' } });

const UPPERCASE_STDIN =
  "let d='';process.stdin.setEncoding('utf8');process.stdin.on('data',(c)=>{d+=c});process.stdin.on('end',()=>{process.stdout.write(d.toUpperCase())})";

describe('spawnCapture file I/O', () => {
  let root: string;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-runner-io-'));
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  it('streams stdinFile into the child and captures stdout', async () => {
    const input = path.join(root, 'input.txt');
    await fs.writeFile(input, 'hello file stdin', 'utf8');

    const r = await spawnCapture({
      file: process.execPath,
      argv: ['-e', UPPERCASE_STDIN],
      env: env(),
      timeoutMs: 10_000,
      maxOutputBytes: 1024,
      stdinFile: input,
    });

    expect(r.exitCode).toBe(0);
    expect(r.stdout).toBe('HELLO FILE STDIN');
    expect(r.stdoutBytes).toBe(16);
    expect(r.ioError).toBeUndefined();
    expect(r.spawnError).toBeUndefined();
  });

  it('streams stdout to stdoutFile and keeps stdout empty', async () => {
    const out = path.join(root, 'out.txt');
    const payload = 'written to file';

    const r = await spawnCapture({
      file: process.execPath,
      argv: ['-e', `process.stdout.write(${JSON.stringify(payload)});process.exit(0)`],
      env: env(),
      timeoutMs: 10_000,
      maxOutputBytes: 1024,
      stdoutFile: out,
    });

    expect(r.exitCode).toBe(0);
    expect(r.stdout).toBe('');
    expect(r.stdoutBytes).toBe(Buffer.byteLength(payload));
    expect(r.stdoutTruncated).toBe(false);
    await expect(fs.readFile(out, 'utf8')).resolves.toBe(payload);
  });

  it('stops at maxOutputBytes, kills the tree, and truncates the file', async () => {
    const out = path.join(root, 'limited.txt');
    const started = Date.now();

    const r = await spawnCapture({
      file: process.execPath,
      argv: [
        '-e',
        "process.stdout.write('x'.repeat(4096)); setInterval(()=>{}, 1000)",
      ],
      env: env(),
      timeoutMs: 15_000,
      maxOutputBytes: 100,
      stdoutFile: out,
    });

    expect(r.stdoutTruncated).toBe(true);
    expect(r.stdout).toBe('');
    expect(r.stdoutBytes).toBeGreaterThan(100);
    expect(r.timedOut).toBe(false);
    // 杀树后应很快返回，而不是等满 timeoutMs。
    expect(Date.now() - started).toBeLessThan(10_000);
    expect((await fs.stat(out)).size).toBe(100);
  });

  it('fails without spawning when stdinFile cannot be opened', async () => {
    const marker = path.join(root, 'spawned.txt');
    const script = `require('fs').writeFileSync(${JSON.stringify(marker)}, 'x')`;

    const r = await spawnCapture({
      file: process.execPath,
      argv: ['-e', script],
      env: env(),
      timeoutMs: 5000,
      maxOutputBytes: 1024,
      stdinFile: path.join(root, 'missing.txt'),
    });

    expect(r.exitCode).toBeNull();
    expect(r.stdout).toBe('');
    expect(r.ioError?.stream).toBe('stdin');
    expect(r.ioError?.code).toBe('ENOENT');
    await expect(fs.access(marker)).rejects.toThrow();
  });

  it('fails without spawning when stdoutFile cannot be opened', async () => {
    const dir = path.join(root, 'a-directory');
    await fs.mkdir(dir);

    const r = await spawnCapture({
      file: process.execPath,
      argv: ['-e', 'process.stdout.write("never")'],
      env: env(),
      timeoutMs: 5000,
      maxOutputBytes: 1024,
      stdoutFile: dir,
    });

    expect(r.exitCode).toBeNull();
    expect(r.ioError?.stream).toBe('stdout');
    expect(typeof r.ioError?.code).toBe('string');
    expect(r.ioError?.message.length).toBeGreaterThan(0);
  });

  it('rejects stdinData together with stdinFile', async () => {
    await expect(
      spawnCapture({
        file: process.execPath,
        argv: ['-e', 'process.exit(0)'],
        env: env(),
        timeoutMs: 5000,
        maxOutputBytes: 1024,
        stdinData: 'x',
        stdinFile: path.join(root, 'input.txt'),
      }),
    ).rejects.toThrow(TypeError);
  });
});

describe('captureStdoutAsBuffer', () => {
  it('returns the full buffer and byte count under the limit', async () => {
    const r = await captureStdoutAsBuffer(Readable.from([Buffer.from('ab'), Buffer.from('cd')]), 100);
    expect(r.truncated).toBe(false);
    expect(r.bytes).toBe(4);
    expect(r.buffer?.toString('utf8')).toBe('abcd');
  });

  it('returns buffer=null as soon as the limit is exceeded', async () => {
    const r = await captureStdoutAsBuffer(Readable.from([Buffer.from('x'.repeat(500))]), 40);
    expect(r.truncated).toBe(true);
    expect(r.buffer).toBeNull();
    expect(r.bytes).toBe(500);
  });

  it('preserves multi-byte text exactly under the limit', async () => {
    const text = '中文😀测试';
    const r = await captureStdoutAsBuffer(Readable.from([Buffer.from(text, 'utf8')]), 1000);
    expect(r.truncated).toBe(false);
    expect(r.buffer?.toString('utf8')).toBe(text);
  });
});

describe('runSftp', () => {
  it('spawns the sftp binary when it is available', async () => {
    try {
      await resolveToolBinary('sftp');
    } catch {
      return; // 本机没有 sftp：跳过
    }
    // 非法选项不会触网：sftp 打印 usage 后退出。
    const r = await runSftp({
      argv: ['-h'],
      timeoutMs: 10_000,
      maxOutputBytes: 64 * 1024,
      env: env(),
      label: 'sftp-usage',
    });
    expect(`${r.stdout}${r.stderr}`).toMatch(/usage:\s*sftp/i);
    expect(r.spawnError).toBeUndefined();
  });
});
