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

/** 剥离结果：`stripped=false` 且带 `reason` 表示拒绝改变语义，调用方必须原样拒绝。 */
export interface SudoStripResult {
  /** 可安全执行的命令；无法安全剥离时为原命令。 */
  command: string;
  /** 是否移除了前导提权程序。 */
  stripped: boolean;
  /** 不能安全剥离的原因。存在时 command 原样返回，调用方应拒绝而不是以 root 执行。 */
  reason?: string;
  /** 该拒绝对应的硬规则 id（hard-sudo/hard-su/...）。仅 reason 存在时设置。 */
  ruleId?: string;
}

/** 提权程序 -> 内置 hard 规则 id（与 command-defaults 保持一致）。 */
const SUDO_PROGRAM_RULES: Readonly<Record<string, string>> = {
  sudo: 'hard-sudo',
  su: 'hard-su',
  doas: 'hard-doas',
  pkexec: 'hard-pkexec',
};

/** sudo 中不改变执行身份/环境的短选项：-n / -S / -k。 */
const SAFE_SUDO_SHORT: ReadonlySet<string> = new Set(['n', 'S', 'k']);
/** sudo 中不改变执行身份/环境的长选项。 */
const SAFE_SUDO_LONG: ReadonlySet<string> = new Set([
  'non-interactive',
  'stdin',
  'reset-timestamp',
]);

/** 会改变提权语义的短选项（原因用于错误 hint）。 */
const SUDO_SEMANTIC_SHORT: ReadonlyMap<string, string> = new Map([
  ['g', '执行组'],
  ['D', '工作目录'],
  ['r', 'SELinux 角色'],
  ['t', 'SELinux 类型'],
  ['C', '文件描述符'],
  ['h', '目标主机'],
  ['U', '其他用户'],
  ['R', 'chroot 目录'],
  ['T', '命令超时'],
  ['E', '环境变量'],
  ['H', 'HOME'],
  ['P', '组向量'],
]);

/** 会改变提权语义的长选项。 */
const SUDO_SEMANTIC_LONG: ReadonlyMap<string, string> = new Map([
  ['--group', '执行组'],
  ['--chdir', '工作目录'],
  ['--role', 'SELinux 角色'],
  ['--type', 'SELinux 类型'],
  ['--close-from', '文件描述符'],
  ['--host', '目标主机'],
  ['--other-user', '其他用户'],
  ['--chroot', 'chroot 目录'],
  ['--command-timeout', '命令超时'],
  ['--login-class', '登录类'],
  ['--preserve-env', '环境变量'],
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

type ParseOutcome =
  | { kind: 'ok'; nextIndex: number; suInner?: string }
  | { kind: 'refuse'; reason: string };

function refuse(reason: string): ParseOutcome {
  return { kind: 'refuse', reason };
}

/**
 * 解析 sudo 选项。只接受不影响执行身份/环境的选项白名单：
 * -n/--non-interactive、-S/--stdin、-k/--reset-timestamp、-p/--prompt <arg>、
 * `--`、以及 -u/--user root。
 * 其余（-u 非 root、-g、-D、-r、-t、-C、-h、-U、-R、-T、-E...）一律拒绝剥离。
 */
function parseSudoOptions(tokens: readonly TokenSpan[], start: number): ParseOutcome {
  let i = start;
  while (i < tokens.length) {
    const word = tokens[i]?.value ?? '';
    if (word === '--') return { kind: 'ok', nextIndex: i + 1 };
    if (!word.startsWith('-')) return { kind: 'ok', nextIndex: i };

    if (word.startsWith('--')) {
      const eq = word.indexOf('=');
      const name = eq === -1 ? word : word.slice(0, eq);
      const inline = eq === -1 ? undefined : word.slice(eq + 1);

      if (name === '--user') {
        let value = inline;
        let consume = 1;
        if (value === undefined) {
          const arg = tokens[i + 1];
          if (arg === undefined) return refuse('sudo --user 缺少用户名参数');
          value = arg.value;
          consume = 2;
        }
        if (value !== 'root') {
          return refuse(
            `sudo --user 指定了非 root 用户 "${value}"；剥离前缀会以 root 执行，改变语义`,
          );
        }
        i += consume;
        continue;
      }

      if (name === '--prompt') {
        if (inline === undefined) {
          if (tokens[i + 1] === undefined) return refuse('sudo --prompt 缺少参数');
          i += 2;
        } else {
          i += 1;
        }
        continue;
      }

      if (SAFE_SUDO_LONG.has(word.slice(2))) {
        i += 1;
        continue;
      }

      const semantic = SUDO_SEMANTIC_LONG.get(name);
      if (semantic !== undefined) {
        return refuse(`sudo 选项 ${name} 会改变提权语义（${semantic}）；不能安全剥离`);
      }
      return refuse(`不支持的 sudo 选项 ${name}；不能安全剥离`);
    }

    // 短选项簇，例如 -n、-Sk、-nu root。
    const cluster = word.slice(1);
    if (cluster.length === 0) return refuse('sudo 选项 - 无法安全解释；不能安全剥离');
    let consume = 1;
    for (let c = 0; c < cluster.length; c++) {
      const ch = cluster[c] ?? '';
      if (SAFE_SUDO_SHORT.has(ch)) continue;
      if (ch === 'u' || ch === 'p') {
        let value = cluster.slice(c + 1);
        if (value === '') {
          const arg = tokens[i + 1];
          if (arg === undefined) return refuse(`sudo -${ch} 缺少参数`);
          value = arg.value;
          consume = 2;
        }
        if (ch === 'u' && value !== 'root') {
          return refuse(
            `sudo -u 指定了非 root 用户 "${value}"；剥离前缀会以 root 执行，改变语义`,
          );
        }
        break; // 该选项后的字符都属于参数。
      }
      const semantic = SUDO_SEMANTIC_SHORT.get(ch);
      if (semantic !== undefined) {
        return refuse(`sudo 选项 -${ch} 会改变提权语义（${semantic}）；不能安全剥离`);
      }
      return refuse(`不支持的 sudo 选项 -${ch}；不能安全剥离`);
    }
    i += consume;
  }
  return { kind: 'ok', nextIndex: i };
}

/**
 * doas：只有裸 `doas <cmd>` 可安全剥离。
 * `-u` 会切换目标用户，其余选项也会改变行为，因此一律原样返回。
 */
function parseDoasOptions(tokens: readonly TokenSpan[], start: number): ParseOutcome {
  const word = tokens[start]?.value ?? '';
  if (word === '' || !word.startsWith('-')) return { kind: 'ok', nextIndex: start };
  if (word.includes('u')) {
    return refuse('doas -u 会切换目标用户；剥离前缀会以 root 执行，改变语义');
  }
  return refuse(`doas 选项 ${word} 会改变执行语义；不能安全剥离`);
}

/** pkexec：只有裸 `pkexec <cmd>` 可安全剥离；`--user` 等选项一律拒绝。 */
function parsePkexecOptions(tokens: readonly TokenSpan[], start: number): ParseOutcome {
  const word = tokens[start]?.value ?? '';
  if (word === '' || !word.startsWith('-')) return { kind: 'ok', nextIndex: start };
  if (word === '--user' || word.startsWith('--user=')) {
    return refuse('pkexec --user 会切换目标用户；剥离前缀会以 root 执行，改变语义');
  }
  return refuse(`pkexec 选项 ${word} 会改变执行语义；不能安全剥离`);
}

/**
 * su：只有 `su -c <cmd>`（不带目标用户）可安全剥离。
 * 目标用户位置参数、-s/-g/-u 等选项都会改变身份或环境，原样返回。
 */
function parseSuOptions(tokens: readonly TokenSpan[], start: number): ParseOutcome {
  let i = start;
  let inner: string | undefined;
  while (i < tokens.length) {
    const word = tokens[i]?.value ?? '';
    if (word === '--') return { kind: 'ok', nextIndex: i + 1, suInner: inner };
    if (word === '-') {
      // 登录 shell：仍以 root 运行，不改变目标身份。
      i += 1;
      continue;
    }
    if (!word.startsWith('-')) {
      // 位置参数：目标用户。
      return refuse(`su 指定了目标用户 "${word}"；剥离前缀会以 root 执行，改变语义`);
    }

    if (word.startsWith('--')) {
      const eq = word.indexOf('=');
      const name = eq === -1 ? word : word.slice(0, eq);
      const inline = eq === -1 ? undefined : word.slice(eq + 1);
      if (name === '--command') {
        let value = inline;
        let consume = 1;
        if (value === undefined) {
          const arg = tokens[i + 1];
          if (arg === undefined) return refuse('su --command 缺少参数');
          value = arg.value;
          consume = 2;
        }
        if (inner !== undefined) return refuse('su 重复指定 --command；不能安全剥离');
        inner = value;
        i += consume;
        continue;
      }
      if (name === '--login') {
        i += 1;
        continue;
      }
      return refuse(`su 选项 ${name} 会改变执行语义；不能安全剥离`);
    }

    const cluster = word.slice(1);
    let consumed = 1;
    for (let c = 0; c < cluster.length; c++) {
      const ch = cluster[c] ?? '';
      if (ch === 'l') continue;
      if (ch === 'c') {
        let value = cluster.slice(c + 1);
        if (value === '') {
          const arg = tokens[i + 1];
          if (arg === undefined) return refuse('su -c 缺少参数');
          value = arg.value;
          consumed = 2;
        }
        if (inner !== undefined) return refuse('su 重复指定 -c；不能安全剥离');
        inner = value;
        break;
      }
      return refuse(`su 选项 -${ch} 会改变执行语义；不能安全剥离`);
    }
    i += consumed;
  }
  return { kind: 'ok', nextIndex: i, ...(inner !== undefined ? { suInner: inner } : {}) };
}

function stripRefused(
  command: string,
  programName: string,
  reason: string,
): SudoStripResult {
  return {
    command,
    stripped: false,
    reason,
    ruleId: SUDO_PROGRAM_RULES[programName] ?? 'hard-sudo',
  };
}

/**
 * 剥离命令开头冗余的 `sudo`/`su`/`doas`/`pkexec` 及其选项，返回内部命令。
 *
 * ssh_sudo 本身已经用 sudo 包装命令；用户传入 `sudo systemctl ...` 时若不去除，
 * 会被内置 hard-sudo 规则误拒，或在远端形成嵌套 sudo。只有语义安全的形式
 * （裸 sudo、-n/-S/-k/-p、`--`、`-u root`，或 `su -c <cmd>` 不带目标用户）才会被剥离；
 * 任何会改变执行身份/环境的选项都原样返回并附 reason，由调用方让 hard 规则拒绝，
 * 绝不静默以 root 执行。
 *
 * 环境赋值与 `command`/`builtin` 前缀保留在其原位置。
 */
export function stripLeadingSudoCommand(command: string): SudoStripResult {
  if (!isSudoCommand(command)) return { command, stripped: false };
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
  if (program === undefined) return { command, stripped: false };
  const programName = basenameOf(program.value);
  if (!SUDO_PROGRAMS.has(programName)) return { command, stripped: false };

  const outcome =
    programName === 'sudo'
      ? parseSudoOptions(tokens, index + 1)
      : programName === 'su'
        ? parseSuOptions(tokens, index + 1)
        : programName === 'doas'
          ? parseDoasOptions(tokens, index + 1)
          : parsePkexecOptions(tokens, index + 1);

  if (outcome.kind === 'refuse') {
    return stripRefused(command, programName, outcome.reason);
  }

  if (programName === 'su') {
    if (outcome.suInner === undefined) {
      return stripRefused(command, programName, 'su 未通过 -c 指定命令；剥离前缀会改变语义');
    }
    const rest = tokens[outcome.nextIndex];
    if (rest !== undefined) {
      return stripRefused(
        command,
        programName,
        `su 指定了目标用户 "${rest.value}"；剥离前缀会以 root 执行，改变语义`,
      );
    }
    // 保留 -c 参数之后的 shell 运算符（scanLeadingTokens 在 `;`/`&`/`|` 处停止）。
    const tailStart = tokens[tokens.length - 1]?.end ?? command.length;
    return {
      command: `${command.slice(0, program.start)}${outcome.suInner}${command.slice(tailStart)}`,
      stripped: true,
    };
  }

  const rest = tokens[outcome.nextIndex];
  if (rest === undefined) {
    return stripRefused(
      command,
      programName,
      `${programName} 后面没有要执行的命令；不能安全剥离`,
    );
  }
  return {
    command: `${command.slice(0, program.start)}${command.slice(rest.start)}`,
    stripped: true,
  };
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
