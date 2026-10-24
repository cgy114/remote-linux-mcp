import { UsageError } from '../errors/classes.js';
import { validateCwd, validateExecInput, validateRemoteEnv } from './remote-command.js';

/** 会话空闲超时范围。 */
export const MIN_IDLE_TIMEOUT_MS = 1_000;
export const MAX_IDLE_TIMEOUT_MS = 86_400_000;

/** 单条会话命令的超时范围。 */
export const MIN_COMMAND_TIMEOUT_MS = 1;
export const MAX_COMMAND_TIMEOUT_MS = 600_000;

/** 单条会话命令的输出上限范围。 */
export const MIN_MAX_OUTPUT_BYTES = 4096;
export const MAX_MAX_OUTPUT_BYTES = 8_388_608;

const NONCE_RE = /^[0-9a-f]{32}$/;
const FORBIDDEN_LINE_RE = /[\u0000\r\n]/;

export interface SessionStartInput {
  cwd?: string;
  env?: Record<string, string>;
  idle_timeout_ms?: number;
}

export interface SessionSendInput {
  command: string;
  timeout_ms?: number;
  max_output_bytes?: number;
}

export interface SessionBootstrapInput {
  /** 32 个小写十六进制字符。 */
  nonce: string;
  /** 由 renderCwd 生成的 shell 表达式。 */
  cwdExpr: string;
  /** 由 renderEnvExports 生成的 `export KEY='VALUE'` 行。 */
  envLines: readonly string[];
}

function invalid(code: string, message: string): UsageError {
  return new UsageError(message, { code });
}

function assertIntegerInRange(
  field: string,
  value: unknown,
  min: number,
  max: number,
  code: string,
): void {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    throw invalid(code, `${field} must be an integer in ${min}..${max}`);
  }
}

function assertInputObject(input: unknown, code: string): void {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw invalid(code, 'input must be an object');
  }
}

/**
 * 校验 session_start 输入：cwd 走远端路径规则，env 复用 ssh_exec 的 env 规则，
 * idle_timeout_ms 为 1s..24h 的整数。任何失败抛带 code 的 UsageError。
 */
export function validateSessionStartInput(input: SessionStartInput): void {
  assertInputObject(input, 'invalid_session_start');
  if (input.cwd !== undefined) validateCwd(input.cwd);
  validateRemoteEnv(input.env);
  if (input.idle_timeout_ms !== undefined) {
    assertIntegerInRange(
      'idle_timeout_ms',
      input.idle_timeout_ms,
      MIN_IDLE_TIMEOUT_MS,
      MAX_IDLE_TIMEOUT_MS,
      'invalid_idle_timeout',
    );
  }
}

/**
 * 校验 session_send 输入：command 与 ssh_exec 同规则（非空、安全文本、≤16 KiB），
 * timeout_ms 为 1ms..10min，max_output_bytes 为 4 KiB..8 MiB，均为整数。
 */
export function validateSessionSendInput(input: SessionSendInput): void {
  assertInputObject(input, 'invalid_session_send');
  validateExecInput({ command: input.command });
  if (input.timeout_ms !== undefined) {
    assertIntegerInRange(
      'timeout_ms',
      input.timeout_ms,
      MIN_COMMAND_TIMEOUT_MS,
      MAX_COMMAND_TIMEOUT_MS,
      'invalid_timeout',
    );
  }
  if (input.max_output_bytes !== undefined) {
    assertIntegerInRange(
      'max_output_bytes',
      input.max_output_bytes,
      MIN_MAX_OUTPUT_BYTES,
      MAX_MAX_OUTPUT_BYTES,
      'invalid_max_output',
    );
  }
}

/**
 * 生成远端 bootstrap 脚本行。
 *
 * 数据流约定：
 * - fd3 是 ssh channel 的副本（`exec 3>&1`），控制帧只写 fd3，用户命令
 *   `exec >file` 不会吞掉帧；
 * - 远端 stderr 合并到 stdout（`exec 2>&1`），P4 只有一个输出流；
 * - 每条命令以 `<seq> <encodeScript payload>` 一行送入 stdin，用
 *   `builtin printf %b` 还原后 eval；eval 的 stdin 指向 /dev/null，
 *   不会抢走协议行；
 * - eval 前后都 `set +e`：用户命令里的 errexit 不会终止会话循环，也不会
 *   让非零退出码跳过 E 帧；
 * - eval 后立即 `exec 1>&3 2>&3` 重新锚定 fd1/fd2，用户命令的
 *   `exec >file` 只影响该条命令，不会吞掉后续输出/帧；
 * - 收到 `Q` 时跳出循环，最终把 fd1/fd2 恢复到 channel。
 *
 * 所有 printf 均使用 builtin，变量名固定为 RMCP_*，因此用户 env 无法劫持
 * 协议路径（bootstrap 本身不含任何用户命令）。
 */
export function buildSessionBootstrap(input: SessionBootstrapInput): string[] {
  const { nonce, cwdExpr, envLines } = input;

  if (typeof nonce !== 'string' || !NONCE_RE.test(nonce)) {
    throw new TypeError('nonce must be 32 lowercase hex characters');
  }
  if (typeof cwdExpr !== 'string' || cwdExpr.length === 0 || FORBIDDEN_LINE_RE.test(cwdExpr)) {
    throw new TypeError('cwdExpr must be a non-empty single-line string');
  }
  if (!Array.isArray(envLines)) {
    throw new TypeError('envLines must be an array');
  }
  for (const line of envLines) {
    if (typeof line !== 'string' || line.includes('\u0000') || !line.startsWith('export ')) {
      throw new TypeError('envLines must contain "export ..." lines without NUL');
    }
  }

  return [
    'exec 3>&1; exec 2>&1',
    ...envLines,
    `builtin cd -- ${cwdExpr} || exit 125`,
    `trap 'exec 1>&3 2>&3' EXIT`,
    `RMCP_NONCE='${nonce}'`,
    `builtin printf '\\036RMCP%s:RDY\\037' "$RMCP_NONCE" >&3`,
    'while IFS= read -r RMCP_LINE; do',
    '  RMCP_SEQ=${RMCP_LINE%% *}',
    '  RMCP_PAYLOAD=${RMCP_LINE#* }',
    '  case "$RMCP_SEQ" in',
    '    Q) break ;;',
    '  esac',
    `  builtin printf '\\036RMCP%s:B:%s\\037' "$RMCP_NONCE" "$RMCP_SEQ" >&3`,
    // 每条命令都从非 errexit 状态开始：用户上一条命令里的 `set -e` 不应让
    // 下一条命令的非零退出码直接终止会话循环。
    '  set +e',
    '  eval "$(builtin printf %b "$RMCP_PAYLOAD")" </dev/null',
    '  RMCP_RC=$?',
    // 用户命令可能重定向了 fd1/fd2；先恢复协议通道，再写 E 帧与后续输出。
    '  exec 1>&3 2>&3',
    // 命令本身可能刚开启 errexit，写帧前再关一次。
    '  set +e',
    `  builtin printf '\\036RMCP%s:E:%s:%s\\037' "$RMCP_NONCE" "$RMCP_SEQ" "$RMCP_RC" >&3`,
    'done',
    'exec 1>&3 2>&3',
  ];
}
