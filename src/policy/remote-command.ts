import { createHash } from 'node:crypto';
import { UsageError } from '../errors/classes.js';
import { assertSafeText, hasLoneSurrogate, shSingleQuote } from './shell.js';

/** 远端命令的长度门限（UTF-16 单元数与 UTF-8 字节数）。 */
export interface ExecSizeLimits {
  maxRemoteUtf16: number;
  maxRemoteUtf8: number;
}

/** P2 ssh_exec 的默认门限：28000 UTF-16 / 1 MiB UTF-8。 */
export const DEFAULT_EXEC_LIMITS: ExecSizeLimits = {
  maxRemoteUtf16: 28_000,
  maxRemoteUtf8: 1024 * 1024,
};

/** 前置校验所需的输入子集；cwd 可省略（真实 cwd 在构建阶段才确定）。 */
export interface ExecValidationInput {
  command: string;
  /** 远端 cwd；省略时跳过 cwd 校验。 */
  cwd?: string;
  env?: Record<string, string>;
  /** stdin 内容；提供时会校验字节数与 NUL。 */
  stdin?: string | Buffer;
  /** 未提供 stdin 内容时，可只声明字节数（≤1 MiB）。 */
  stdinBytes?: number;
}

export interface ExecCommandInput extends ExecValidationInput {
  cwd: string;
  limits: ExecSizeLimits;
}

export interface ExecCommandPlan {
  bashScript: string;
  payload: string;
  remoteCommand: string;
  commandSha256: string;
  commandBytes: number;
  cwd: string;
  envKeys: string[];
  stdinBytes: number;
}

/** 单条命令的最大 UTF-8 字节数（16 KiB）。 */
export const MAX_COMMAND_BYTES = 16 * 1024;
/** stdin 内容的最大字节数（1 MiB）。 */
export const MAX_STDIN_BYTES = 1024 * 1024;
const MAX_ENV_BYTES = 16 * 1024;
const MAX_ENV_ENTRIES = 64;
const MAX_CWD_LENGTH = 4096;

const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const FORBIDDEN_ENV_KEYS: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype']);
const CWD_FORBIDDEN_RE = /[\u0000\r\n]/;

function usage(code: string, message: string): UsageError {
  return new UsageError(message, { code });
}

/**
 * 校验远端 cwd：以 `/` 或 `~` 开头、≤4096、无 NUL/CR/LF/孤立 surrogate。
 * 只允许 `~` 与 `~/...`；`~user` 一律拒绝。
 */
export function assertRemoteCwd(cwd: unknown): string {
  if (typeof cwd !== 'string' || cwd.length === 0) {
    throw usage('invalid_cwd', 'remote cwd must be a non-empty string');
  }
  if (cwd[0] !== '/' && cwd[0] !== '~') {
    throw usage('invalid_cwd', 'remote cwd must start with "/" or "~"');
  }
  if (cwd.length > MAX_CWD_LENGTH) {
    throw usage('invalid_cwd', `remote cwd longer than ${MAX_CWD_LENGTH} characters`);
  }
  if (CWD_FORBIDDEN_RE.test(cwd) || hasLoneSurrogate(cwd)) {
    throw usage('invalid_cwd', 'remote cwd must not contain NUL, newline or lone surrogates');
  }
  if (cwd.startsWith('~') && cwd !== '~' && !cwd.startsWith('~/')) {
    throw usage('invalid_cwd', 'remote cwd must use "~" or "~/..." (not "~user")');
  }
  return cwd;
}

function assertEnvKey(key: string): void {
  if (!ENV_KEY_RE.test(key)) {
    throw usage('invalid_env', `invalid environment variable name ${JSON.stringify(key)}`);
  }
  if (FORBIDDEN_ENV_KEYS.has(key)) {
    throw usage('invalid_env', `environment variable name ${JSON.stringify(key)} is not allowed`);
  }
}

function assertEnvValue(key: string, value: unknown): string {
  if (typeof value !== 'string') {
    throw usage('invalid_env', `environment variable ${JSON.stringify(key)} must have a string value`);
  }
  if (value.includes('\u0000') || hasLoneSurrogate(value)) {
    throw usage('invalid_env', `environment variable ${JSON.stringify(key)} value contains NUL or lone surrogates`);
  }
  return value;
}

/** 校验远端 cwd（规则见 assertRemoteCwd）；失败抛 invalid_cwd。 */
export function validateCwd(cwd: unknown): string {
  return assertRemoteCwd(cwd);
}

/**
 * 校验远端 env 块：对象映射、≤64 条、键必须匹配 `/^[A-Za-z_][A-Za-z0-9_]*$/`
 * 且不是原型键、值不允许 NUL/孤立 surrogate、键值 UTF-8 合计 ≤16 KiB。
 * `undefined` 视为未提供。失败抛 invalid_env。
 */
export function validateRemoteEnv(env: unknown): void {
  if (env === undefined) return;
  if (typeof env !== 'object' || env === null || Array.isArray(env)) {
    throw usage('invalid_env', 'env must be an object mapping names to string values');
  }
  const entries = Object.entries(env);
  if (entries.length > MAX_ENV_ENTRIES) {
    throw usage('invalid_env', `at most ${MAX_ENV_ENTRIES} environment variables are allowed`);
  }
  let totalBytes = 0;
  for (const [key, value] of entries) {
    assertEnvKey(key);
    const v = assertEnvValue(key, value);
    totalBytes += Buffer.byteLength(key, 'utf8') + Buffer.byteLength(v, 'utf8');
  }
  if (totalBytes > MAX_ENV_BYTES) {
    throw usage('invalid_env', `environment block exceeds ${MAX_ENV_BYTES} UTF-8 bytes`);
  }
}

/** 校验 exec 输入；cwd 省略时不校验 cwd。任何失败都以带 code 的 UsageError 抛出。 */
export function validateExecInput(input: ExecValidationInput): void {
  const { command } = input;
  if (typeof command !== 'string' || command.length === 0) {
    throw usage('invalid_command', 'command must be a non-empty string');
  }
  assertSafeText(command, { field: 'command', code: 'invalid_command' });
  if (Buffer.byteLength(command, 'utf8') > MAX_COMMAND_BYTES) {
    throw usage('command_too_large', `command exceeds ${MAX_COMMAND_BYTES} UTF-8 bytes`);
  }

  if (input.stdin !== undefined) {
    if (typeof input.stdin === 'string') {
      assertSafeText(input.stdin, { field: 'stdin', code: 'invalid_stdin' });
    } else if (input.stdin.includes(0)) {
      throw usage('invalid_stdin', 'stdin must not contain a NUL byte');
    }
    if (Buffer.byteLength(input.stdin) > MAX_STDIN_BYTES) {
      throw usage('invalid_stdin', `stdin exceeds ${MAX_STDIN_BYTES} bytes`);
    }
  } else if (input.stdinBytes !== undefined) {
    if (
      typeof input.stdinBytes !== 'number' ||
      !Number.isInteger(input.stdinBytes) ||
      input.stdinBytes < 0 ||
      input.stdinBytes > MAX_STDIN_BYTES
    ) {
      throw usage('invalid_stdin', `stdinBytes must be an integer in 0..${MAX_STDIN_BYTES}`);
    }
  }

  validateRemoteEnv(input.env);

  if (input.cwd !== undefined) validateCwd(input.cwd);
}

/** `~` -> `"$HOME"`；`~/x` -> `"$HOME"'/x'`；绝对路径 -> 单引号；`~user` 拒绝。 */
export function renderCwd(cwd: string): string {
  const checked = assertRemoteCwd(cwd);
  if (checked === '~') return '"$HOME"';
  if (checked.startsWith('~/')) return `"$HOME"${shSingleQuote(checked.slice(1))}`;
  return shSingleQuote(checked);
}

/** 按键字典序生成 `export KEY='VALUE'` 行；键非法抛 invalid_env。 */
export function renderEnvExports(env: Record<string, string> | undefined): string[] {
  if (env === undefined) return [];
  return Object.keys(env)
    .sort()
    .map((key) => {
      assertEnvKey(key);
      const value = assertEnvValue(key, env[key]);
      return `export ${key}=${shSingleQuote(value)}`;
    });
}

/** env 行 + `builtin cd -- <cwdExpr> || exit 125` + 原样 command（command 前保证换行）。 */
export function buildBashScript(input: {
  cwdExpr: string;
  envLines: readonly string[];
  command: string;
}): string {
  const lines = [...input.envLines, `builtin cd -- ${input.cwdExpr} || exit 125`];
  return `${lines.join('\n')}\n${input.command}`;
}

const ESCAPED_ASCII: ReadonlySet<string> = new Set(["'", '"', '$', '`', '\\', '!']);

/**
 * 把脚本（UTF-8 字节）编码为 ASCII payload：可打印 ASCII 原样保留，
 * 但 `' " $ \` \\ !` 与所有非可打印字节写成 `\xHH`（大写十六进制）。
 */
export function encodeScript(script: string): string {
  const bytes = Buffer.from(script, 'utf8');
  let out = '';
  for (const b of bytes) {
    if (b >= 0x20 && b <= 0x7e) {
      const ch = String.fromCharCode(b);
      if (!ESCAPED_ASCII.has(ch)) {
        out += ch;
        continue;
      }
    }
    out += `\\x${b.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return out;
}

/**
 * 包成远端命令：`/bin/bash -lc '<eval "$(printf %b "<payload>")">'`。
 * payload 只含可打印 ASCII 与 `\xHH`，不会出现未转义的 `"`。
 */
export function wrapPayload(payload: string): string {
  const inner = `eval "$(printf %b "${payload}")"`;
  return `/bin/bash -lc ${shSingleQuote(inner)}`;
}

/** 远端命令长度门限（UTF-16 与 UTF-8 双重检查）。 */
export function assertRemoteSize(remoteCommand: string, limits: ExecSizeLimits): void {
  if (
    remoteCommand.length > limits.maxRemoteUtf16 ||
    Buffer.byteLength(remoteCommand, 'utf8') > limits.maxRemoteUtf8
  ) {
    throw usage('command_too_large', 'encoded remote command exceeds the configured size limit');
  }
}

/** 校验 -> 引用 -> 编码 -> 包装 -> 长度门限，返回可交给 ssh 的单条远端命令。 */
export function buildExecCommand(input: ExecCommandInput): ExecCommandPlan {
  validateExecInput(input);

  const cwdExpr = renderCwd(input.cwd);
  const envLines = renderEnvExports(input.env);
  const bashScript = buildBashScript({ cwdExpr, envLines, command: input.command });
  const payload = encodeScript(bashScript);
  const remoteCommand = wrapPayload(payload);
  assertRemoteSize(remoteCommand, input.limits);

  const stdinBytes =
    input.stdin !== undefined ? Buffer.byteLength(input.stdin) : (input.stdinBytes ?? 0);

  return {
    bashScript,
    payload,
    remoteCommand,
    commandSha256: createHash('sha256').update(input.command, 'utf8').digest('hex'),
    commandBytes: Buffer.byteLength(input.command, 'utf8'),
    cwd: input.cwd,
    envKeys: Object.keys(input.env ?? {}).sort(),
    stdinBytes,
  };
}
