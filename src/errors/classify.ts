import { redact } from '../log.js';
import type { Logger, RunResult, SshSignatures, ErrorFacts, ErrorKind, ToolError } from '../types.js';
import { makeToolError } from './taxonomy.js';

const POLICY_REASON_RE = /^(invalid_|unknown_alias$|policy_)/;
const HOSTKEY_REASONS = new Set(['not_registered', 'known_hosts_missing', 'fingerprint_mismatch']);

const DNS_RE = /could not resolve hostname|name or service not known|nodename nor servname|temporary failure in name resolution/i;
const TCP_RE = /connection refused|connection reset|no route to host|network is unreachable|connection closed by .* port/i;
const AUTH_RE = /permission denied \(publickey|too many authentication failures|load key|sign_and_send_pubkey|no such identity/i;
const HOSTKEY_CHANGED_RE = /remote host identification has changed|host key verification failed|offending .* key in .*:(\d+)/i;
const HOSTKEY_UNKNOWN_RE = /the authenticity of host|no .* host key is known|host key for .* has changed and you have requested strict checking/i;
const SUDO_RE = /\[sudo\] password for|sudo: a password is required|sudo: a terminal is required|sudo: no tty present/i;
const TIMEOUT_RE = /connection timed out|operation timed out|timeout, server .* not responding/i;

const OTHER_MAX_LINES = 3;
const OTHER_MAX_LINE_CHARS = 300;
const STDERR_TAIL_MAX_CHARS = 2000;

/** 按 reason 给出的更具体指引（优先于类别 hint）。<alias> 由 formatToolError 在提供 alias 时替换。 */
const REASON_HINTS: Record<string, string> = {
  not_registered: '该主机尚未登记主机密钥。运行 `remote-mcp trust <alias>` 完成首次信任。',
  known_hosts_missing: 'known_hosts 文件缺失或不含该主机。运行 `remote-mcp trust <alias>` 重新登记。',
  fingerprint_mismatch: '远端主机指纹与已固定的不一致。确认主机合法后运行 `remote-mcp trust <alias>`；否则排查中间人风险。',
  unknown_alias: '配置中不存在该 alias。检查拼写，或在配置文件中添加对应 host。',
};

function signaturesOf(facts: ErrorFacts): Partial<SshSignatures> {
  return facts.signatures ?? {};
}

/**
 * 纯函数分类，绝不抛。固定优先级：
 * Policy > Internal > Timeout > HostKey > SudoPrompt > Auth > DNS > TCP > RemoteExit > Unknown。
 */
export function classify(facts: ErrorFacts): ErrorKind {
  try {
    const sig = signaturesOf(facts);
    const reason = typeof facts.reason === 'string' ? facts.reason : undefined;

    if (facts.phase === 'config' || (reason !== undefined && POLICY_REASON_RE.test(reason))) {
      return 'Policy';
    }
    if (facts.spawnError !== undefined && facts.spawnError !== null) {
      return 'Internal';
    }
    if (facts.timedOut === true || sig.connectionTimeout === true) {
      return 'Timeout';
    }
    if (
      sig.hostKeyChanged === true ||
      sig.hostKeyUnknown === true ||
      (reason !== undefined && HOSTKEY_REASONS.has(reason))
    ) {
      return 'HostKey';
    }
    if (sig.sudoPrompt === true || reason === 'sudo_prompt') {
      return 'SudoPrompt';
    }
    if (sig.auth === true) {
      return 'Auth';
    }
    if (sig.dns === true) {
      return 'DNS';
    }
    if (sig.tcp === true) {
      return 'TCP';
    }
    const code = facts.exitCode;
    if (
      (typeof code === 'number' && Number.isInteger(code) && code >= 1 && code <= 254) ||
      reason === 'remote_exit'
    ) {
      return 'RemoteExit';
    }
    return 'Unknown';
  } catch {
    return 'Unknown';
  }
}

/**
 * 从 stderr 提取事实（不决定类别）。匹配不区分大小写。
 * other 仅在非空且无任何特征命中时，取末尾最多 3 行（每行截断 300 字符）。
 */
export function stderrSignatures(stderr: string): SshSignatures {
  const text = typeof stderr === 'string' ? stderr : '';
  const sig: SshSignatures = {
    dns: DNS_RE.test(text),
    tcp: TCP_RE.test(text),
    auth: AUTH_RE.test(text),
    hostKeyChanged: HOSTKEY_CHANGED_RE.test(text),
    hostKeyUnknown: HOSTKEY_UNKNOWN_RE.test(text),
    sudoPrompt: SUDO_RE.test(text),
    connectionTimeout: TIMEOUT_RE.test(text),
    other: [],
  };
  const anyHit =
    sig.dns || sig.tcp || sig.auth || sig.hostKeyChanged || sig.hostKeyUnknown || sig.sudoPrompt || sig.connectionTimeout;
  if (!anyHit && text.trim().length > 0) {
    sig.other = text
      .split(/\r?\n/)
      .filter((line) => line.trim().length > 0)
      .slice(-OTHER_MAX_LINES)
      .map((line) => line.slice(0, OTHER_MAX_LINE_CHARS));
  }
  return sig;
}

/** 把 RunResult 的退出事实转换为 ErrorFacts 片段。 */
export function classifyExit(
  run: Pick<RunResult, 'exitCode' | 'timedOut' | 'signal' | 'spawnError'>,
): Partial<ErrorFacts> {
  if (run.spawnError !== undefined && run.spawnError !== null) {
    return { spawnError: run.spawnError };
  }
  if (run.timedOut === true) {
    return { timedOut: true };
  }
  const code = run.exitCode;
  if (code === 255) {
    return { exitCode: 255, reason: 'ssh_transport_failure' };
  }
  if (typeof code === 'number' && code >= 1 && code <= 254) {
    return { exitCode: code, reason: 'remote_exit' };
  }
  if (code === 0) {
    return { exitCode: 0 };
  }
  if (run.signal !== undefined && run.signal !== null && run.signal !== '') {
    return { signal: run.signal };
  }
  return {};
}

/**
 * 把事实转为用户可见错误。不抛异常。
 * details 含 exitCode、timedOut、经脱敏并截断到末尾 2000 字符的 stderr。
 */
export function toUserError(facts: ErrorFacts, log?: Logger): ToolError {
  try {
    const kind = classify(facts);
    const details: Record<string, unknown> = {};
    if (facts.exitCode !== undefined && facts.exitCode !== null) details['exitCode'] = facts.exitCode;
    if (facts.timedOut === true) details['timedOut'] = true;
    if (typeof facts.stderr === 'string' && facts.stderr.length > 0) {
      const safe = String(redact(facts.stderr));
      details['stderr'] = safe.length > STDERR_TAIL_MAX_CHARS ? safe.slice(-STDERR_TAIL_MAX_CHARS) : safe;
    }
    const err = makeToolError(kind, { details });
    const specificHint = typeof facts.reason === 'string' ? REASON_HINTS[facts.reason] : undefined;
    if (specificHint !== undefined) {
      err.hint = specificHint;
    }
    try {
      log?.debug({ kind, code: err.code, reason: facts.reason, phase: facts.phase }, 'ssh failure classified');
    } catch {
      // 日志失败不影响错误返回
    }
    return err;
  } catch {
    return makeToolError('Unknown');
  }
}

/** 多行文本渲染。alias 存在时替换 hint 中的 <alias>；stderr 尾部再次脱敏。 */
export function formatToolError(err: ToolError, alias?: string): string {
  const lines: string[] = [`[${err.kind}] ${err.code}: ${err.message}`];
  if (alias !== undefined) {
    lines.push(`host: ${alias}`);
  }
  if (err.hint !== undefined) {
    lines.push(`hint: ${alias !== undefined ? err.hint.split('<alias>').join(alias) : err.hint}`);
  }
  const details = err.details;
  if (details !== undefined) {
    if (typeof details['exitCode'] === 'number') {
      lines.push(`exitCode: ${details['exitCode']}`);
    }
    if (details['timedOut'] === true) {
      lines.push('timedOut: true');
    }
    if (typeof details['stderr'] === 'string' && details['stderr'].length > 0) {
      const safe = String(redact(details['stderr']));
      lines.push('stderr:');
      for (const line of safe.split(/\r?\n/)) {
        lines.push(`  ${line}`);
      }
    }
  }
  return lines.join('\n');
}
