import { makeToolError } from '../errors/taxonomy.js';
import type { RunResult, ToolError } from '../types.js';
import { leadingWords } from './command-scan.js';
import {
  assertRemoteSize,
  buildExecCommand,
  type ExecCommandPlan,
  type ExecSizeLimits,
} from './remote-command.js';
import { shSingleQuote } from './shell.js';

export type SudoMode = 'passwordless' | 'password';

export interface SudoRemoteInput {
  command: string;
  mode: SudoMode;
  limits: ExecSizeLimits;
  /** 远端 cwd；默认 `~`（sudo 的登录 shell 会以 root 的 HOME 解析）。 */
  cwd?: string;
}

export interface SudoRemotePlan {
  /** buildExecCommand 生成的内部执行计划（校验、编码与长度门限均已通过）。 */
  inner: ExecCommandPlan;
  /** 可直接交给 ssh 的远端命令。 */
  remoteCommand: string;
  sudoMode: SudoMode;
}

const SUDO_SUPPORTED_RE = /Sorry, try again|incorrect password|password is required|terminal is required|no tty present|no password was provided/i;

const SUDO_PROGRAMS: ReadonlySet<string> = new Set(['sudo', 'su', 'doas', 'pkexec']);

/**
 * 构造 sudo 远端命令：
 * - passwordless: `sudo -n -- bash -lc <inner script>`
 * - password:     `sudo -S -k -p '' -- bash -lc <inner script>`
 *
 * inner 计划复用 buildExecCommand（cwd 校验、env 引用、大小限制）。
 */
export function buildSudoRemoteCommand(input: SudoRemoteInput): SudoRemotePlan {
  const inner = buildExecCommand({
    command: input.command,
    cwd: input.cwd ?? '~',
    limits: input.limits,
  });
  const quotedScript = shSingleQuote(inner.bashScript);
  const prefix = input.mode === 'passwordless' ? 'sudo -n -- ' : "sudo -S -k -p '' -- ";
  const remoteCommand = `${prefix}/bin/bash -lc ${quotedScript}`;
  assertRemoteSize(remoteCommand, input.limits);
  return { inner, remoteCommand, sudoMode: input.mode };
}

/** sudo -S 的 stdin：密码 + 换行 + 可选的用户 stdin。 */
export function composeSudoStdin(password: Buffer, userStdin?: Buffer): Buffer {
  const newline = Buffer.from('\n');
  if (userStdin === undefined || userStdin.length === 0) {
    return Buffer.concat([password, newline]);
  }
  return Buffer.concat([password, newline, userStdin]);
}

/** stderr 出现 sudo 密码/终端提示特征时返回 SudoPrompt 错误，否则 undefined。 */
export function classifySudoRun(run: Pick<RunResult, 'stderr'>): ToolError | undefined {
  if (typeof run.stderr !== 'string' || !SUDO_SUPPORTED_RE.test(run.stderr)) return undefined;
  return makeToolError('SudoPrompt');
}

/** 命令的首个有效 token 是否直接是 sudo/su/doas/pkexec。 */
export function isSudoCommand(command: string): boolean {
  const first = leadingWords(command, 1)[0];
  return first !== undefined && SUDO_PROGRAMS.has(first);
}
