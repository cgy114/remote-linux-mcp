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

/** 远端从 stdin 解包到指定目录。 */
export function buildRemoteTarExtractCommand(
  remoteDir: string,
  opts: { gzip?: boolean } = {},
): string {
  return `tar -C ${renderRemoteShellPath(remoteDir)} ${tarFlags(false, opts.gzip === true)} -`;
}

export interface RunLocalTarInput {
  argv: readonly string[];
  timeoutMs?: number;
  maxOutputBytes?: number;
  cwd?: string;
  stdinFile?: string;
  stdoutFile?: string;
  label?: string;
  /** 测试可注入；默认解析系统 tar。 */
  binary?: string;
}

/** 运行本地 tar（stdinFile/stdoutFile 用于流式管道）。 */
export async function runLocalTar(input: RunLocalTarInput): Promise<RunResult> {
  const file = input.binary ?? (await resolveToolBinary('tar'));
  return spawnCapture({
    file,
    argv: input.argv,
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

/** 本地创建 tar 归档（stdout 流式写入 archive，不经过内存）。 */
export async function createLocalArchive(input: CreateLocalArchiveInput): Promise<RunResult> {
  const source = path.resolve(input.source);
  const contents = input.contents === true;
  const dir = contents ? source : path.dirname(source);
  const base = contents ? '.' : path.basename(source);
  return runLocalTar({
    argv: ['-C', dir, tarFlags(true, input.gzip === true), '-', '--', base],
    stdoutFile: path.resolve(input.archive),
    ...(input.timeoutMs !== undefined ? { timeoutMs: input.timeoutMs } : {}),
    ...(input.binary !== undefined ? { binary: input.binary } : {}),
    label: 'local tar create',
  });
}

export interface ExtractLocalArchiveInput {
  archive: string;
  destDir: string;
  gzip?: boolean;
  timeoutMs?: number;
  binary?: string;
}

/** 本地解包归档到 destDir。 */
export async function extractLocalArchive(input: ExtractLocalArchiveInput): Promise<RunResult> {
  return runLocalTar({
    argv: ['-C', path.resolve(input.destDir), tarFlags(false, input.gzip === true), path.resolve(input.archive)],
    ...(input.timeoutMs !== undefined ? { timeoutMs: input.timeoutMs } : {}),
    ...(input.binary !== undefined ? { binary: input.binary } : {}),
    label: 'local tar extract',
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
