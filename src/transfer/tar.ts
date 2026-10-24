import { promises as fs } from 'node:fs';
import path from 'node:path';
import { UsageError } from '../errors/classes.js';
import { basenameRemote, dirnameRemote, renderRemoteShellPath } from '../policy/remote-path.js';
import { shSingleQuote } from '../policy/shell.js';
import { resolveToolBinary } from '../ssh/binary.js';
import { buildChildEnv } from '../ssh/env.js';
import { spawnCapture } from '../ssh/runner.js';
import type { RunResult, ToolError } from '../types.js';
import { runRemoteCommand, type TransferDeps } from './deps.js';
import { classifyTransportRun, remoteFailure, stderrTail } from './errors.js';

export interface RemoteTarOptions {
  /** 归档目录内容（"."）而不是目录本身。 */
  contents?: boolean;
  gzip?: boolean;
}

function tarUsage(message: string): UsageError {
  return new UsageError(message, { code: 'remote_path_invalid' });
}

function tarFlags(create: boolean, gzip: boolean): string {
  if (create) return gzip ? '-czf' : '-cf';
  return gzip ? '-xzf' : '-xf';
}

/** 远端创建 tar 并写到 stdout。默认归档路径本身，contents=true 时归档其内容。 */
export function buildRemoteTarCreateCommand(
  remotePath: string,
  opts: RemoteTarOptions = {},
): string {
  const flags = tarFlags(true, opts.gzip === true);
  if (opts.contents === true) {
    return `tar -C ${renderRemoteShellPath(remotePath)} ${flags} - .`;
  }
  const dir = dirnameRemote(remotePath);
  const base = basenameRemote(remotePath);
  if (base === '/' || base === '~') throw tarUsage('cannot archive a filesystem root');
  return `tar -C ${renderRemoteShellPath(dir)} ${flags} - -- ${shSingleQuote(base)}`;
}

const IS_WIN = process.platform === 'win32';

export interface LocalTarBinary {
  path: string;
  /** 需要前置到 argv 的额外参数（GNU tar 用 --force-local）。 */
  argsPrefix: readonly string[];
  /** GNU tar（MSYS）：路径必须使用正斜杠。 */
  gnu: boolean;
}

/**
 * Windows 上查找 Git 自带的 GNU tar。System32 的 bsdtar 会按 ANSI 代码页
 * 解释归档中的 UTF-8 文件名（中文乱码），因此优先使用 GNU tar。
 * PATH 里常见的是 <Git>/usr/bin、<Git>/cmd 或 <Git>/mingw64/bin。
 */
async function findGitGnuTar(): Promise<string | undefined> {
  const dirs = (process.env.PATH ?? '').split(path.delimiter).filter((dir) => dir.length > 0);
  const candidates: string[] = [];
  for (const dir of dirs) {
    if (/[\\/]Git[\\/]usr[\\/]bin[\\/]?$/i.test(dir)) {
      candidates.push(path.join(dir, 'tar.exe'));
    } else if (/[\\/]Git[\\/]cmd[\\/]?$/i.test(dir)) {
      candidates.push(path.join(dir, '..', 'usr', 'bin', 'tar.exe'));
    } else if (/[\\/]Git[\\/]mingw64[\\/]bin[\\/]?$/i.test(dir)) {
      candidates.push(path.join(dir, '..', '..', 'usr', 'bin', 'tar.exe'));
    }
  }
  for (const candidate of candidates) {
    try {
      await fs.access(candidate);
      return path.resolve(candidate);
    } catch {
      // 继续尝试下一个候选。
    }
  }
  return undefined;
}

/**
 * 解析本地 tar：Windows 优先 Git GNU tar（--force-local + 正斜杠路径），
 * 找不到时回退系统 tar；POSIX 直接使用系统 tar。
 */
export async function resolveLocalTarBinary(): Promise<LocalTarBinary> {
  if (IS_WIN) {
    const gnu = await findGitGnuTar();
    if (gnu !== undefined) {
      return { path: gnu, argsPrefix: ['--force-local'], gnu: true };
    }
  }
  return { path: await resolveToolBinary('tar'), argsPrefix: [], gnu: false };
}

/** GNU tar 需要正斜杠路径；系统 tar 保持原样。 */
export function localTarPath(binary: LocalTarBinary, value: string): string {
  return binary.gnu ? value.replace(/\\/g, '/') : value;
}

export interface RunLocalTarInput {
  argv: readonly string[];
  timeoutMs?: number;
  maxOutputBytes?: number;
  cwd?: string;
  stdinFile?: string;
  stdoutFile?: string;
  label?: string;
  /** 测试可注入路径；默认按平台解析（见 resolveLocalTarBinary）。 */
  binary?: string | LocalTarBinary;
}

/** 运行本地 tar（stdinFile/stdoutFile 用于流式管道）。 */
export async function runLocalTar(input: RunLocalTarInput): Promise<RunResult> {
  const binary =
    typeof input.binary === 'string'
      ? { path: input.binary, argsPrefix: [], gnu: false }
      : (input.binary ?? (await resolveLocalTarBinary()));
  return spawnCapture({
    file: binary.path,
    argv: [...binary.argsPrefix, ...input.argv],
    env: buildChildEnv(),
    timeoutMs: input.timeoutMs ?? 300_000,
    maxOutputBytes: input.maxOutputBytes ?? 1_048_576,
    ...(input.cwd !== undefined ? { cwd: input.cwd } : {}),
    ...(input.stdinFile !== undefined ? { stdinFile: input.stdinFile } : {}),
    ...(input.stdoutFile !== undefined ? { stdoutFile: input.stdoutFile } : {}),
  });
}

export interface CreateLocalArchiveInput {
  source: string;
  archive: string;
  contents?: boolean;
  gzip?: boolean;
  timeoutMs?: number;
  binary?: string;
}

/**
 * 本地创建 tar 归档（stdout 流式写入 archive，不经过内存）。
 *
 * 归档创建固定使用系统 tar（Windows 上是 System32 bsdtar）：它把文件模式记为
 * 0666，与 Node 在 Windows 上报告的本地清单 mode 一致；Git 的 GNU tar 会记为
 * 0644，远端 `tar -xpf` 解包后与上传清单不符（verify_manifest_mismatch）。
 * 下载方向的本地解包仍优先 GNU tar（见 resolveLocalTarBinary）。
 */
export async function createLocalArchive(input: CreateLocalArchiveInput): Promise<RunResult> {
  const binary = input.binary ?? (await resolveToolBinary('tar'));
  const source = path.resolve(input.source);
  const contents = input.contents === true;
  const dir = contents ? source : path.dirname(source);
  const base = contents ? '.' : path.basename(source);
  return runLocalTar({
    argv: ['-C', dir, tarFlags(true, input.gzip === true), '-', '--', base],
    binary,
    stdoutFile: path.resolve(input.archive),
    ...(input.timeoutMs !== undefined ? { timeoutMs: input.timeoutMs } : {}),
    label: 'local tar create',
  });
}

export interface RunRemoteTarOptions {
  stdinFile?: string;
  stdoutFile?: string;
  timeoutMs?: number;
  label?: string;
}

/** 执行远端 tar；stdinFile/stdoutFile 用于本地两进程流式管道。 */
export async function runRemoteTar(
  deps: TransferDeps,
  command: string,
  opts: RunRemoteTarOptions = {},
): Promise<RunResult> {
  return runRemoteCommand(deps, command, {
    ...(opts.stdinFile !== undefined ? { stdinFile: opts.stdinFile } : {}),
    ...(opts.stdoutFile !== undefined ? { stdoutFile: opts.stdoutFile } : {}),
    ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    label: opts.label ?? `tar:${deps.target.host.alias}`,
  });
}

/** tar 运行事实 -> 错误；0 为成功。 */
export function tarFailure(run: RunResult): ToolError | undefined {
  if (
    run.spawnError !== undefined ||
    run.ioError !== undefined ||
    run.timedOut ||
    (run.signal !== null && run.signal !== '')
  ) {
    return classifyTransportRun(run, { label: 'tar' });
  }
  if (run.exitCode === 0) return undefined;
  const details: Record<string, unknown> = {};
  if (run.exitCode !== null) details['exitCode'] = run.exitCode;
  if (run.stderr.length > 0) details['stderr'] = stderrTail(run.stderr);
  return remoteFailure(
    'tar_failed',
    `tar exited with ${run.exitCode === null ? 'no status' : `code ${run.exitCode}`}`,
    details,
  );
}
