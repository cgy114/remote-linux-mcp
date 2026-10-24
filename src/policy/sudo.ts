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
 * - passwordless: `LC_ALL=C sudo -n -- bash -lc <inner script>`
 * - password:     `LC_ALL=C sudo -S -k -p '' -- bash -lc <inner script>`
 *
 * `LC_ALL=C` 保证 sudo 的提示（如 "Sorry, try again."）为英文，
 * 使 classifySudoRun 的英文特征匹配不受远端 locale 影响。
 * inner 计划复用 buildExecCommand（cwd 校验、env 引用、大小限制）。
 */
export function buildSudoRemoteCommand(input: SudoRemoteInput): SudoRemotePlan {
  const inner = buildExecCommand({
    command: input.command,
    cwd: input.cwd ?? '~',
    limits: input.limits,
  });
  const quotedScript = shSingleQuote(inner.bashScript);
  const prefix =
    input.mode === 'passwordless' ? 'LC_ALL=C sudo -n -- ' : "LC_ALL=C sudo -S -k -p '' -- ";
  const remoteCommand = `${prefix}/bin/bash -lc ${quotedScript}`;
  assertRemoteSize(remoteCommand, input.limits);
  return { inner, remoteCommand, sudoMode: input.mode };
}

/** 带独立参数的 sudo 类选项（长选项用 `=` 形式时不消耗下一个 token）。 */
const OPTIONS_WITH_ARGUMENT: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  [
    'sudo',
    new Set([
      '-u', '--user',
      '-g', '--group',
      '-p', '--prompt',
      '-r', '--role',
      '-t', '--type',
      '-U', '--other-user',
      '-C', '--close-from',
      '-T', '--command-timeout',
      '-D', '--chdir',
      '-R', '--chroot',
      '-h', '--host',
    ]),
  ],
  ['doas', new Set(['-u', '-C'])],
  ['pkexec', new Set(['--user'])],
  [
    'su',
    new Set([
      '-c', '--command',
      '-s', '--shell',
      '-g', '--group',
      '-G', '--supp-group',
      '-u', '--user',
      '-w', '--whitelist-environment',
    ]),
  ],
]);

const ENV_ASSIGN_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;

interface TokenSpan {
  /** 去引号/反转义后的值。 */
  value: string;
  start: number;
  end: number;
}

/**
 * 扫描命令开头的 token（保留原始偏移），遇到 `;`、`&`、`|`、`<`、`>` 停止。
 * 只用于剥离前导 sudo/doas/pkexec/su。
 */
function scanLeadingTokens(command: string): TokenSpan[] {
  const spans: TokenSpan[] = [];
  let i = 0;
  while (i < command.length) {
    while (i < command.length && /\s/.test(command[i] ?? '')) i++;
    if (i >= command.length) break;
    const lead = command[i] ?? '';
    if (lead === ';' || lead === '&' || lead === '|' || lead === '<' || lead === '>') break;
    const start = i;
    let value = '';
    let inSingle = false;
    let inDouble = false;
    while (i < command.length) {
      const ch = command[i] ?? '';
      if (inSingle) {
        if (ch === "'") inSingle = false;
        else value += ch;
        i++;
        continue;
      }
      if (inDouble) {
        if (ch === '\\' && i + 1 < command.length) {
          value += command[i + 1] ?? '';
          i += 2;
          continue;
        }
        if (ch === '"') inDouble = false;
        else value += ch;
        i++;
        continue;
      }
      if (ch === '\\' && i + 1 < command.length) {
        value += command[i + 1] ?? '';
        i += 2;
        continue;
      }
      if (ch === "'") {
        inSingle = true;
        i++;
        continue;
      }
      if (ch === '"') {
        inDouble = true;
        i++;
        continue;
      }
      if (/\s/.test(ch) || ch === ';' || ch === '&' || ch === '|' || ch === '<' || ch === '>') break;
      value += ch;
      i++;
    }
    spans.push({ value, start, end: i });
  }
  return spans;
}

/**
 * 剥离命令开头冗余的 `sudo`/`su`/`doas`/`pkexec` 及其选项，返回内部命令。
 *
 * ssh_sudo 本身已经用 sudo 包装命令；用户传入 `sudo systemctl ...` 时若不去除，
 * 会被内置 hard-sudo 规则误拒，或在远端形成嵌套 sudo。无法安全解释时（选项缺参数、
 * `su` 没有 `-c`、剥离后为空）原样返回，让策略以保守方式拒绝。
 *
 * 环境赋值与 `command`/`builtin` 前缀保留在其原位置。
 */
export function stripLeadingSudoCommand(command: string): string {
  if (!isSudoCommand(command)) return command;
  const tokens = scanLeadingTokens(command);
  let index = 0;
  while (index < tokens.length && ENV_ASSIGN_RE.test(tokens[index]?.value ?? '')) index++;
  while (index < tokens.length) {
    const word = tokens[index]?.value ?? '';
    if (word !== 'command' && word !== 'builtin') break;
    index++;
    while (index < tokens.length && (tokens[index]?.value ?? '').startsWith('-')) index++;
  }

  const program = tokens[index];
  if (program === undefined) return command;
  const programName = basenameOf(program.value);
  if (!SUDO_PROGRAMS.has(programName)) return command;
  index++;

  const withArgument = OPTIONS_WITH_ARGUMENT.get(programName) ?? new Set<string>();
  let suInner: string | undefined;
  while (index < tokens.length) {
    const token = tokens[index];
    if (token === undefined) break;
    const word = token.value;
    if (word === '--') {
      index++;
      break;
    }
    // su 的单独 `-` 表示登录 shell。
    if (programName === 'su' && word === '-') {
      index++;
      continue;
    }
    if (!word.startsWith('-')) break;
    if (word.includes('=')) {
      index++;
      continue;
    }
    const takesArgument = withArgument.has(word);
    index++;
    if (!takesArgument) continue;
    const argument = tokens[index];
    if (argument === undefined) return command;
    if (programName === 'su' && (word === '-c' || word === '--command')) {
      suInner = argument.value;
    }
    index++;
  }

  if (programName === 'su') {
    // su 的语义依赖用户/登录 shell；只有明确 `-c <cmd>` 才能安全地只保留内部命令。
    if (suInner === undefined) return command;
    return `${command.slice(0, program.start)}${suInner}`;
  }

  const rest = tokens[index];
  if (rest === undefined) return command;
  const stripped = `${command.slice(0, program.start)}${command.slice(rest.start)}`;
  return stripped.trim().length === 0 ? command : stripped;
}

/**
 * sudo -S 的 stdin：密码 + 换行 + 可选的用户 stdin。
 *
 * ssh_sudo 的 password 模式没有用户 stdin（输入边界不接受 stdin），因此生产调用
 * 只传 password；userStdin 保留用于 API 对称性与单元测试，不改变密码语义。
 */
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

/** 取程序名（与策略层一致：`/usr/bin/sudo` 按 `sudo` 比较）。 */
function basenameOf(token: string): string {
  return token.includes('/') ? (token.split('/').pop() ?? token) : token;
}

/** 命令的首个有效 token 是否是 sudo/su/doas/pkexec（允许绝对路径）。 */
export function isSudoCommand(command: string): boolean {
  const first = leadingWords(command, 1)[0];
  return first !== undefined && SUDO_PROGRAMS.has(basenameOf(first));
}
