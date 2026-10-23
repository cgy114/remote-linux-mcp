import path from 'node:path';
import { UsageError } from '../errors/classes.js';
import { hasLoneSurrogate } from '../policy/shell.js';
import type { RunResult } from '../types.js';
import { runSftpSteps, type RunSftpOptions, type TransferDeps } from './deps.js';

const FORBIDDEN_RE = /[\u0000\r\n]/;

function sftpUsage(message: string): UsageError {
  return new UsageError(message, { code: 'remote_path_invalid' });
}

/**
 * sftp batch 路径引用：始终用双引号包裹，转义 `\` 与 `"`。
 * 空路径、NUL/CR/LF、孤立 surrogate 一律拒绝（batch 不允许裸换行）。
 */
export function quoteSftpPath(p: string): string {
  if (typeof p !== 'string' || p.length === 0) {
    throw sftpUsage('sftp path must be a non-empty string');
  }
  if (FORBIDDEN_RE.test(p) || hasLoneSurrogate(p)) {
    throw sftpUsage('sftp path must not contain NUL, CR, LF or lone surrogates');
  }
  const escaped = p.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  return `"${escaped}"`;
}

/** 本地路径在 sftp batch 中统一用 "/"（Windows 反斜杠会破坏 batch 转义）。 */
export function normalizeLocalSftpPath(p: string): string {
  if (path.sep === '/') return p;
  return p.split(path.sep).join('/');
}

function localForBatch(p: string): string {
  return quoteSftpPath(normalizeLocalSftpPath(p));
}

export function putStep(local: string, remote: string): string {
  return `put ${localForBatch(local)} ${quoteSftpPath(remote)}`;
}

export function getStep(remote: string, local: string): string {
  return `get ${quoteSftpPath(remote)} ${localForBatch(local)}`;
}

export function renameStep(from: string, to: string): string {
  return `rename ${quoteSftpPath(from)} ${quoteSftpPath(to)}`;
}

/** 删除文件（目录请用 rmdirStep / removeRemoteTree）。 */
export function removeStep(remote: string): string {
  return `rm ${quoteSftpPath(remote)}`;
}

export function rmdirStep(remote: string): string {
  return `rmdir ${quoteSftpPath(remote)}`;
}

export function mkdirStep(remote: string): string {
  return `mkdir ${quoteSftpPath(remote)}`;
}

function parseMode(mode: number | string): string {
  let value: number;
  if (typeof mode === 'number') {
    value = mode;
  } else {
    if (!/^[0-7]{1,6}$/.test(mode)) throw sftpUsage('sftp chmod mode must be octal');
    value = Number.parseInt(mode, 8);
  }
  if (!Number.isInteger(value) || value < 0) {
    throw sftpUsage('sftp chmod mode must be a non-negative integer');
  }
  // 与清单一致：只下发权限位，忽略文件类型/特殊位。
  return (value & 0o777).toString(8);
}

export function chmodStep(mode: number | string, remote: string): string {
  return `chmod ${parseMode(mode)} ${quoteSftpPath(remote)}`;
}

/** 把步骤拼成 batch 文本；每步独占一行，末尾保证一个换行。 */
export function buildSftpBatch(steps: readonly string[]): string {
  if (steps.length === 0) return '';
  for (const step of steps) {
    if (typeof step !== 'string' || step.length === 0) {
      throw sftpUsage('sftp batch step must be a non-empty string');
    }
    if (FORBIDDEN_RE.test(step)) {
      throw sftpUsage('sftp batch step must not contain NUL, CR or LF');
    }
  }
  return `${steps.join('\n')}\n`;
}

/** 执行一批 sftp 步骤；返回运行事实（不做退出码分类）。 */
export async function runSftpBatch(
  deps: TransferDeps,
  steps: readonly string[],
  opts: RunSftpOptions = {},
): Promise<RunResult> {
  buildSftpBatch(steps);
  return runSftpSteps(deps, steps, opts);
}

/** 只诊断 sftp 运行事实，不改变/不包装错误。 */
export function sftpDiagnostics(run: RunResult): string[] {
  const out: string[] = [];
  if (run.spawnError !== undefined) {
    out.push(`sftp could not start (${run.spawnError.code})`);
  }
  if (run.ioError !== undefined) {
    out.push(`local ${run.ioError.stream} I/O failed (${run.ioError.code})`);
  }
  if (run.timedOut) out.push('sftp timed out');
  const stderr = run.stderr;
  if (/permission denied/i.test(stderr)) out.push('permission denied on the remote path');
  if (/no such file|not found/i.test(stderr)) out.push('remote path not found');
  if (/not a directory/i.test(stderr)) out.push('remote path component is not a directory');
  if (/is a directory/i.test(stderr)) out.push('remote path is a directory');
  if (/failure|failed/i.test(stderr)) out.push('sftp reported a failure');
  if (/could not resolve|connection refused|connection (closed|reset)|broken pipe|kex_exchange/i.test(stderr)) {
    out.push('ssh transport problem');
  }
  if (out.length === 0 && run.exitCode !== null && run.exitCode !== 0) {
    out.push(`sftp exited with code ${run.exitCode}`);
  }
  return [...new Set(out)];
}
