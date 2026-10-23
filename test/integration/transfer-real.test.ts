import { createHash, randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { CallToolResult } from '@modelcontextprotocol/server';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config/load.js';
import { resolvePaths } from '../../src/config/paths.js';
import { createLogger } from '../../src/log.js';
import { sshDownload } from '../../src/tools/ssh-download.js';
import { sshExec } from '../../src/tools/ssh-exec.js';
import { sshReadFile } from '../../src/tools/ssh-read-file.js';
import { sshUpload } from '../../src/tools/ssh-upload.js';
import { sshWriteFile } from '../../src/tools/ssh-write-file.js';
import type { ToolContext } from '../../src/tools/common.js';
import type { RemoteConfig } from '../../src/types.js';

const E2E = process.env.REMOTE_MCP_E2E === '1';
const ALIAS = 'orangepi';
const TEST_TIMEOUT_MS = 180_000;
const SETUP_TIMEOUT_MS = 120_000;
const IS_WIN = process.platform === 'win32';

const TRANSIENT_CODES = new Set([
  'timeout',
  'transfer_timeout',
  'ssh_transport_failure',
  'tcp_failed',
  'dns_failed',
  'connection_closed',
]);

interface Structured {
  error?: { code?: string; kind?: string };
  [key: string]: unknown;
}

function structured(result: CallToolResult): Structured {
  return (result.structuredContent ?? {}) as Structured;
}

function errorCode(result: CallToolResult): string | undefined {
  return structured(result).error?.code;
}

function stdoutOf(result: CallToolResult): string {
  return String(structured(result)['stdout'] ?? '');
}

function textOf(result: CallToolResult): string {
  return (result.content ?? [])
    .map((item) => (item.type === 'text' ? item.text : ''))
    .join('\n');
}

/** 网络抖动最多重试一次；只对传输层/超时错误重试，逻辑错误原样返回。 */
async function withRetry(
  label: string,
  fn: () => Promise<CallToolResult>,
): Promise<CallToolResult> {
  const first = await fn();
  const code = errorCode(first);
  if (first.isError !== true || code === undefined || !TRANSIENT_CODES.has(code)) return first;
  console.warn(`[e2e] retrying ${label} after transient ${code}`);
  await new Promise((resolve) => setTimeout(resolve, 1500));
  return fn();
}

function sha256(buf: Buffer | string): string {
  return createHash('sha256').update(buf).digest('hex');
}

function shq(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

describe.skipIf(!E2E)('integration: file transfer on real host (orangepi)', () => {
  let base: string;
  let localRoot: string;
  let configDir: string;
  let remoteRoot: string;
  let ctx: ToolContext;
  let config: RemoteConfig;

  async function runRemote(command: string): Promise<CallToolResult> {
    return withRetry(`ssh_exec:${command.slice(0, 40)}`, () =>
      sshExec({ host: ALIAS, command, timeout_ms: 30_000 }, ctx),
    );
  }

  async function remoteSha(file: string): Promise<string> {
    const result = await runRemote(`sha256sum -- ${shq(file)}`);
    expect(result.isError, textOf(result)).not.toBe(true);
    return stdoutOf(result).trim().split(/\s+/)[0]!;
  }

  async function remoteMode(file: string): Promise<string> {
    const result = await runRemote(`stat -c '%a' -- ${shq(file)}`);
    expect(result.isError, textOf(result)).not.toBe(true);
    return stdoutOf(result).trim();
  }

  async function localMode(file: string): Promise<string> {
    return ((await fs.lstat(file)).mode & 0o777).toString(8);
  }

  beforeAll(async () => {
    base = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-e2e-'));
    localRoot = path.join(base, 'local');
    configDir = path.join(base, 'cfg');
    await fs.mkdir(localRoot);
    await fs.mkdir(configDir);

    const realDir = path.join(os.homedir(), '.remote-mcp');
    await fs.copyFile(path.join(realDir, 'known_hosts'), path.join(configDir, 'known_hosts'));
    await fs.copyFile(path.join(realDir, 'trusted.json'), path.join(configDir, 'trusted.json'));

    const configText = [
      'version: 1',
      'defaults:',
      '  timeouts:',
      '    connect_ms: 10000',
      '    command_ms: 30000',
      'files:',
      '  local_roots:',
      `    - ${JSON.stringify(localRoot)}`,
      '  max_file_bytes: 8388608',
      '  max_files: 1000',
      '  max_total_bytes: 33554432',
      '  max_depth: 32',
      '  transfer_timeout_ms: 120000',
      '  verify: manifest',
      'hosts:',
      '  orangepi:',
      '    host: 100.115.38.14',
      '    user: orangepi',
      '    identity_file: "~/.ssh/id_ed25519"',
      '',
    ].join('\n');
    const configPath = path.join(configDir, 'config.yaml');
    await fs.writeFile(configPath, configText, 'utf8');

    const paths = resolvePaths({ explicit: configPath, env: {} });
    config = await loadConfig(paths);
    ctx = {
      paths,
      log: createLogger({ level: 'error' }),
      getConfig: async () => config,
    };

    remoteRoot = `/tmp/rm-e2e-${randomBytes(6).toString('hex')}`;
    const created = await runRemote(`mkdir -p -- ${shq(remoteRoot)}`);
    expect(created.isError, textOf(created)).not.toBe(true);
    console.log(`[e2e] remoteRoot=${remoteRoot} localRoot=${localRoot}`);
  }, SETUP_TIMEOUT_MS);

  afterAll(async () => {
    if (remoteRoot !== undefined && ctx !== undefined) {
      try {
        await sshExec({ host: ALIAS, command: `rm -rf -- ${shq(remoteRoot)}` }, ctx);
      } catch {
        // 清理失败不掩盖测试结果。
      }
    }
    if (base !== undefined) {
      await fs.rm(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  }, SETUP_TIMEOUT_MS);

  it('uploads a text file and the remote sha256 matches', async () => {
    const content = 'hello 中文 😀\n';
    const local = path.join(localRoot, 'hello.txt');
    await fs.writeFile(local, content);
    const expected = sha256(content);

    const result = await withRetry('upload hello.txt', () =>
      sshUpload(
        { host: ALIAS, local_path: local, remote_path: `${remoteRoot}/hello.txt` },
        ctx,
      ),
    );
    console.log('[e2e upload] ' + JSON.stringify(structured(result)));
    expect(result.isError, textOf(result)).not.toBe(true);
    expect(structured(result)['sha256']).toBe(expected);
    expect(structured(result)['file_count']).toBe(1);
    expect(await remoteSha(`${remoteRoot}/hello.txt`)).toBe(expected);
  }, TEST_TIMEOUT_MS);

  it('downloads the file back with identical content', async () => {
    const local = path.join(localRoot, 'roundtrip.txt');
    const result = await withRetry('download hello.txt', () =>
      sshDownload(
        { host: ALIAS, remote_path: `${remoteRoot}/hello.txt`, local_path: local },
        ctx,
      ),
    );
    console.log('[e2e download] ' + JSON.stringify(structured(result)));
    expect(result.isError, textOf(result)).not.toBe(true);
    expect(await fs.readFile(local, 'utf8')).toBe('hello 中文 😀\n');
    expect(structured(result)['sha256']).toBe(sha256('hello 中文 😀\n'));
  }, TEST_TIMEOUT_MS);

  it('reads content, sha256 and encoding via ssh_read_file', async () => {
    const result = await withRetry('read hello.txt', () =>
      sshReadFile({ host: ALIAS, path: `${remoteRoot}/hello.txt` }, ctx),
    );
    console.log('[e2e read] ' + JSON.stringify({ ...structured(result), content: '<omitted>' }));
    expect(result.isError, textOf(result)).not.toBe(true);
    expect(structured(result)['content']).toBe('hello 中文 😀\n');
    expect(structured(result)['encoding']).toBe('utf8');
    expect(structured(result)['sha256']).toBe(sha256('hello 中文 😀\n'));
    expect(structured(result)['size']).toBe(Buffer.byteLength('hello 中文 😀\n'));
    expect(structured(result)['truncated']).toBe(false);
  }, TEST_TIMEOUT_MS);

  it('writes a file atomically, applies mode and verifies remotely', async () => {
    const content = 'written 中文\n';
    const target = `${remoteRoot}/written.txt`;
    const result = await withRetry('write written.txt', () =>
      sshWriteFile(
        { host: ALIAS, path: target, content, encoding: 'utf8', mode: '0640' },
        ctx,
      ),
    );
    console.log('[e2e write] ' + JSON.stringify(structured(result)));
    expect(result.isError, textOf(result)).not.toBe(true);
    expect(structured(result)['sha256']).toBe(sha256(content));
    expect(await remoteSha(target)).toBe(sha256(content));
    const cat = await runRemote(`cat -- ${shq(target)}`);
    expect(cat.isError, textOf(cat)).not.toBe(true);
    expect(stdoutOf(cat)).toBe(content);
    expect(await remoteMode(target)).toBe('640');
  }, TEST_TIMEOUT_MS);

  it('enforces overwrite=false and allows overwrite=true for upload and write', async () => {
    const local = path.join(localRoot, 'hello.txt');

    const refused = await sshUpload(
      {
        host: ALIAS,
        local_path: local,
        remote_path: `${remoteRoot}/hello.txt`,
        overwrite: false,
      },
      ctx,
    );
    expect(refused.isError).toBe(true);
    expect(errorCode(refused)).toBe('target_exists');

    const replaced = await sshUpload(
      {
        host: ALIAS,
        local_path: local,
        remote_path: `${remoteRoot}/hello.txt`,
        overwrite: true,
      },
      ctx,
    );
    expect(replaced.isError, textOf(replaced)).not.toBe(true);
    expect(structured(replaced)['overwritten']).toBe(true);

    const writeRefused = await sshWriteFile(
      { host: ALIAS, path: `${remoteRoot}/written.txt`, content: 'x' },
      ctx,
    );
    expect(writeRefused.isError).toBe(true);
    expect(errorCode(writeRefused)).toBe('target_exists');

    const writeReplaced = await sshWriteFile(
      { host: ALIAS, path: `${remoteRoot}/written.txt`, content: 'x', overwrite: true },
      ctx,
    );
    expect(writeReplaced.isError, textOf(writeReplaced)).not.toBe(true);
    expect(structured(writeReplaced)['overwritten']).toBe(true);
  }, TEST_TIMEOUT_MS);

  it('uploads a directory with manifest verification and downloads it back consistently', async () => {
    const tree = path.join(localRoot, 'tree 中文');
    await fs.mkdir(path.join(tree, 'sub'), { recursive: true });
    await fs.writeFile(path.join(tree, 'a.txt'), 'alpha\n');
    await fs.writeFile(path.join(tree, 'sub', 'b.bin'), Buffer.from([0, 1, 2, 3, 4]));
    await fs.writeFile(path.join(tree, '空格 文件.txt'), 'spaced\n');

    // POSIX 上可以真正设置 0640/0755；Windows 上 chmod 只影响只读位，mode 由文件系统合成。
    await fs.chmod(path.join(tree, 'a.txt'), 0o640).catch(() => undefined);
    await fs.chmod(path.join(tree, 'sub', 'b.bin'), 0o755).catch(() => undefined);
    await fs.chmod(tree, 0o755).catch(() => undefined);

    // Windows 默认没有创建符号链接的权限；失败时显式记录并继续无链接用例。
    let symlinkSupported = false;
    try {
      await fs.symlink('a.txt', path.join(tree, 'link.txt'));
      symlinkSupported = true;
    } catch (err) {
      console.warn(
        `[e2e] symlink upload sub-case skipped: cannot create a local symlink on ${process.platform} (${String((err as { code?: string }).code)})`,
      );
    }

    const remoteTree = `${remoteRoot}/tree-upload`;
    const upload = await withRetry('upload tree', () =>
      sshUpload(
        { host: ALIAS, local_path: tree, remote_path: remoteTree, recursive: true },
        ctx,
      ),
    );
    console.log('[e2e upload tree] ' + JSON.stringify(structured(upload)));
    expect(upload.isError, textOf(upload)).not.toBe(true);
    expect(structured(upload)['file_count']).toBe(3);
    expect(structured(upload)['kind']).toBe('directory');
    expect(structured(upload)['manifest_digest']).toMatch(/^[0-9a-f]{64}$/);

    expect(await remoteSha(`${remoteTree}/a.txt`)).toBe(sha256('alpha\n'));
    expect(await remoteSha(`${remoteTree}/空格 文件.txt`)).toBe(sha256('spaced\n'));

    const expectedA = IS_WIN ? await localMode(path.join(tree, 'a.txt')) : '640';
    const expectedB = IS_WIN ? await localMode(path.join(tree, 'sub', 'b.bin')) : '755';
    expect(await remoteMode(`${remoteTree}/a.txt`)).toBe(expectedA);
    expect(await remoteMode(`${remoteTree}/sub/b.bin`)).toBe(expectedB);

    if (symlinkSupported) {
      const linkCheck = await runRemote(
        `test -L ${shq(`${remoteTree}/link.txt`)} && readlink -- ${shq(`${remoteTree}/link.txt`)}`,
      );
      expect(linkCheck.isError, textOf(linkCheck)).not.toBe(true);
      expect(stdoutOf(linkCheck).trim()).toBe('a.txt');
    }

    // Windows 的 tar 实现无法解出符号链接（需要 SeCreateSymbolicLinkPrivilege）。
    if (symlinkSupported && IS_WIN) {
      console.warn('[e2e] tree download sub-case skipped: Windows cannot extract symlinks');
      return;
    }

    const down = path.join(localRoot, 'tree-download');
    const download = await withRetry('download tree', () =>
      sshDownload(
        { host: ALIAS, remote_path: remoteTree, local_path: down, recursive: true },
        ctx,
      ),
    );
    console.log('[e2e download tree] ' + JSON.stringify(structured(download)));
    expect(download.isError, textOf(download)).not.toBe(true);
    expect(await fs.readFile(path.join(down, 'a.txt'), 'utf8')).toBe('alpha\n');
    expect(await fs.readFile(path.join(down, '空格 文件.txt'), 'utf8')).toBe('spaced\n');
    expect(
      Buffer.compare(await fs.readFile(path.join(down, 'sub', 'b.bin')), Buffer.from([0, 1, 2, 3, 4])),
    ).toBe(0);
  }, TEST_TIMEOUT_MS);

  it('round-trips a filename containing spaces and CJK characters', async () => {
    const name = '空格 中文.txt';
    const content = 'name roundtrip 中文\n';
    const local = path.join(localRoot, name);
    await fs.writeFile(local, content);

    const up = await sshUpload(
      { host: ALIAS, local_path: local, remote_path: `${remoteRoot}/${name}` },
      ctx,
    );
    expect(up.isError, textOf(up)).not.toBe(true);

    const down = path.join(localRoot, '空格 中文-copy.txt');
    const dl = await sshDownload(
      { host: ALIAS, remote_path: `${remoteRoot}/${name}`, local_path: down },
      ctx,
    );
    expect(dl.isError, textOf(dl)).not.toBe(true);
    expect(await fs.readFile(down, 'utf8')).toBe(content);
  }, TEST_TIMEOUT_MS);

  it('refuses to read ~/.ssh/id_ed25519', async () => {
    const result = await sshReadFile({ host: ALIAS, path: '~/.ssh/id_ed25519' }, ctx);
    expect(result.isError).toBe(true);
    expect(errorCode(result)).toBe('remote_denied_read');
  }, TEST_TIMEOUT_MS);

  it('refuses uploads from outside files.local_roots', async () => {
    const outside = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-e2e-outside-'));
    const file = path.join(outside, 'outside.txt');
    await fs.writeFile(file, 'outside');
    try {
      const result = await sshUpload(
        { host: ALIAS, local_path: file, remote_path: `${remoteRoot}/outside.txt` },
        ctx,
      );
      expect(result.isError).toBe(true);
      expect(errorCode(result)).toBe('local_root_not_allowed');
    } finally {
      await fs.rm(outside, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  }, TEST_TIMEOUT_MS);

  it('round-trips a 1 MiB random file with an identical sha256', async () => {
    const data = randomBytes(1024 * 1024);
    const expected = sha256(data);
    const local = path.join(localRoot, 'random-1m.bin');
    await fs.writeFile(local, data);

    const up = await withRetry('upload 1MiB', () =>
      sshUpload(
        { host: ALIAS, local_path: local, remote_path: `${remoteRoot}/random-1m.bin` },
        ctx,
      ),
    );
    console.log('[e2e 1MiB upload] ' + JSON.stringify(structured(up)));
    expect(up.isError, textOf(up)).not.toBe(true);
    expect(structured(up)['sha256']).toBe(expected);
    expect(await remoteSha(`${remoteRoot}/random-1m.bin`)).toBe(expected);

    const down = path.join(localRoot, 'random-1m-copy.bin');
    const dl = await withRetry('download 1MiB', () =>
      sshDownload(
        { host: ALIAS, remote_path: `${remoteRoot}/random-1m.bin`, local_path: down },
        ctx,
      ),
    );
    expect(dl.isError, textOf(dl)).not.toBe(true);
    expect(sha256(await fs.readFile(down))).toBe(expected);
  }, TEST_TIMEOUT_MS);
});
