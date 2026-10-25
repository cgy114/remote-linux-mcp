import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type {
  TransferControl,
  TransferControlResult,
  TransferDeps,
} from '../../../src/transfer/deps.js';
import type { ResolvedTarget } from '../../../src/pipeline/target.js';
import type { LocalSource, LocalTarget } from '../../../src/transfer/local-path.js';
import type { Logger } from '../../../src/types.js';

const state = vi.hoisted(() => ({
  sshCalls: [] as Record<string, unknown>[],
  sftpCalls: [] as Record<string, unknown>[],
  downloadBytes: Buffer.alloc(0),
  baseRun: (): Record<string, unknown> => ({
    argv: [],
    displayCommand: 'cmd',
    exitCode: 0,
    signal: null,
    stdout: '',
    stderr: '',
    stdoutBytes: 0,
    stderrBytes: 0,
    stdoutTruncated: false,
    stderrTruncated: false,
    timedOut: false,
    durationMs: 1,
  }),
}));

vi.mock('../../../src/pipeline/run-command.js', () => ({
  runSshCommand: async (input: Record<string, unknown>) => {
    state.sshCalls.push(input);
    return state.baseRun();
  },
}));

vi.mock('../../../src/ssh/runner.js', () => ({
  runSftp: async (input: Record<string, unknown>) => {
    state.sftpCalls.push(input);
    const batch = String(input['stdinData'] ?? '');
    const match = /^get "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)"\r?$/m.exec(batch);
    if (match !== null) {
      const unescape = (value: string): string => value.replace(/\\(.)/g, '$1');
      await fs.writeFile(unescape(match[2]!), state.downloadBytes);
    }
    return state.baseRun();
  },
}));

const { uploadSingleFile, downloadSingleFile } = await import(
  '../../../src/transfer/single-file.js'
);

const logger: Logger = {
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  child: () => logger,
};

function sha256(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex');
}

function b64(value: string): string {
  return `b64:${Buffer.from(value, 'utf8').toString('base64')}`;
}

function ok(exitCode: number, stdout = ''): TransferControlResult {
  return { exitCode, stdout, timedOut: false, durationMs: 1 };
}

function makeTarget(): ResolvedTarget {
  return {
    config: { defaults: { maxOutputBytes: 1048576 } },
    host: {
      alias: 'web1',
      host: '10.0.0.5',
      user: 'deploy',
      port: 22,
      cwd: '~',
      timeouts: { connectMs: 5000, commandMs: 15_000, checkMs: 8000 },
      maxOutputBytes: 1048576,
      sudo: { mode: 'off', allow: [], deny: [] },
    },
    destination: 'deploy@10.0.0.5:22',
  } as unknown as ResolvedTarget;
}

function makeDeps(control: TransferControl): TransferDeps {
  return {
    target: makeTarget(),
    knownHostsFile: path.join(base, 'known_hosts'),
    log: logger,
    limits: { maxFileBytes: 1024 * 1024, maxFiles: 100, maxTotalBytes: 8 * 1024 * 1024, maxDepth: 16 },
    deadlineMs: Date.now() + 60_000,
    home: '/home/u',
    control,
  };
}

let base: string;

beforeAll(async () => {
  base = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-control-'));
});

afterAll(async () => {
  await fs.rm(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
});

describe('transfer state machine over the control channel', () => {
  it('routes upload probe/verify/swap through control and uses sftp exactly once', async () => {
    state.sshCalls.length = 0;
    state.sftpCalls.length = 0;

    const content = Buffer.from('hello');
    const localPath = path.join(base, 'upload-src.txt');
    await fs.writeFile(localPath, content);
    const stat = await fs.stat(localPath);
    const mode = stat.mode & 0o777;
    const local: LocalSource = {
      path: localPath,
      realPath: localPath,
      kind: 'file',
      size: stat.size,
      mode: stat.mode,
      stat,
    };

    const calls: string[] = [];
    const control: TransferControl = {
      run: async (command) => {
        calls.push(command);
        // 原子换入：staged -> target（并可能 rm 备份）。
        if (command.includes('mv -f --')) return ok(0);
        // 临时文件校验探针：类型/size/mode/realpath/hash。
        if (command.includes('.remote-mcp-tmp-')) {
          return ok(0, `file\t${content.length}\t${mode.toString(8)}\t-\t${sha256(content)}`);
        }
        // 目标不存在：probe 脚本以 exit 3 表达。
        if (command.includes('/home/u/new.txt')) return ok(3, '');
        // 父目录门禁。
        if (command.includes(`p='/home/u'`)) {
          return ok(0, `dir\t0\t755\t${b64('/home/u')}\t-`);
        }
        throw new Error(`unexpected control command: ${command.slice(0, 80)}`);
      },
    };

    const facts = await uploadSingleFile({
      deps: makeDeps(control),
      local,
      remote: '/home/u/new.txt',
      overwrite: false,
      denyWrite: [],
    });

    expect(facts.failure).toBeUndefined();
    expect(facts.ok).toBe(true);
    expect(facts.files).toBe(1);
    expect(facts.bytes).toBe(content.length);
    expect(facts.sha256).toBe(sha256(content));

    // 三次探针（目标、父目录、临时文件）+ 一次 swap 全部走控制通道。
    expect(calls.filter((c) => c.includes('p='))).toHaveLength(3);
    expect(calls.filter((c) => c.includes('mv -f --'))).toHaveLength(1);
    // 数据面仍是一次 sftp（put + chmod 同一批）。
    expect(state.sftpCalls).toHaveLength(1);
    expect(state.sshCalls).toHaveLength(0);
  });

  it('routes download probe through control and keeps a single sftp get', async () => {
    state.sshCalls.length = 0;
    state.sftpCalls.length = 0;

    const content = Buffer.from('download-data');
    state.downloadBytes = content;
    const remote = '/home/u/src.bin';
    const sha = sha256(content);
    const calls: string[] = [];
    const control: TransferControl = {
      run: async (command) => {
        calls.push(command);
        if (command.includes(`p='${remote}'`)) {
          return ok(0, `file\t${content.length}\t644\t${b64(remote)}\t${sha}`);
        }
        throw new Error(`unexpected control command: ${command.slice(0, 80)}`);
      },
    };

    const localTarget: LocalTarget = {
      path: path.join(base, 'download-out.bin'),
      exists: false,
    };

    const facts = await downloadSingleFile({
      deps: makeDeps(control),
      remote,
      localTarget,
      overwrite: false,
      denyRead: [],
    });

    expect(facts.failure).toBeUndefined();
    expect(facts.ok).toBe(true);
    expect(facts.sha256).toBe(sha);
    expect(calls).toHaveLength(1);
    expect(state.sftpCalls).toHaveLength(1);
    expect(state.sshCalls).toHaveLength(0);
    expect(await fs.readFile(localTarget.path)).toEqual(content);
  });
});
