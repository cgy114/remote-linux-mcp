/**
 * 审计/日志共用的文本脱敏。
 *
 * 目标不是“完美识别所有秘密”，而是让常见凭据形态与赋值语法不会以明文落盘。
 * 调用方仍应避免把秘密放进审计记录；这里是最后一道防线。
 */

export const REDACTED = '[REDACTED]';

const PEM_PRIVATE_KEY_RE =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;
const BEARER_RE = /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi;
const ANTHROPIC_KEY_RE = /\bsk-ant-[A-Za-z0-9_-]{16,}/g;
const OPENAI_KEY_RE = /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g;
const GITHUB_TOKEN_RE = /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})/g;
const AWS_ACCESS_KEY_RE = /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b/g;
const URL_USERINFO_RE = /(\b[a-z][a-z0-9+.-]*:\/\/)([^/\s:@]+):([^/\s@]+)@/gi;
const PROXY_COMMAND_RE = /(ProxyCommand=)(?:"[^"]*"|'[^']*'|[^\n]*)/gi;
const ASSIGNMENT_RE =
  /\b(password|passwd|pwd|passphrase|secret|token|api[_-]?key|x-api-key|access[_-]?key|private[_-]?key)\s*([:=])\s*("[^"]*"|'[^']*'|[^\s,;]+)/gi;

/** 对单个字符串做模式脱敏。 */
export function redactAuditText(text: string): string {
  return text
    .replace(PEM_PRIVATE_KEY_RE, '[REDACTED PRIVATE KEY]')
    .replace(BEARER_RE, `Bearer ${REDACTED}`)
    .replace(ANTHROPIC_KEY_RE, REDACTED)
    .replace(OPENAI_KEY_RE, REDACTED)
    .replace(GITHUB_TOKEN_RE, REDACTED)
    .replace(AWS_ACCESS_KEY_RE, REDACTED)
    .replace(URL_USERINFO_RE, `$1${REDACTED}@`)
    .replace(PROXY_COMMAND_RE, `$1${REDACTED}`)
    .replace(ASSIGNMENT_RE, `$1$2${REDACTED}`);
}

/** 键名本身表示秘密时整体替换。 */
const SENSITIVE_KEY_RE =
  /(?:password|passwd|pwd|passphrase|secret|token|authorization|api[-_]?key|private[-_]?key|credential|cookie|set-cookie)/i;

/**
 * 递归脱敏任意 JSON 可序列化值：
 * - 字符串走 redactAuditText
 * - 敏感键整体替换为 [REDACTED]
 * - 循环引用替换为 [Circular]
 * - 不修改输入
 */
export function redactAuditRecord(value: unknown): unknown {
  const ancestors = new Set<object>();

  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') return redactAuditText(v);
    if (v === null || typeof v !== 'object') return v;
    if (ancestors.has(v)) return '[Circular]';

    ancestors.add(v);
    try {
      if (Array.isArray(v)) return v.map((item) => walk(item));
      if (v instanceof Date) return v.toISOString();
      const out: Record<string, unknown> = {};
      for (const [key, child] of Object.entries(v)) {
        out[key] = SENSITIVE_KEY_RE.test(key) ? REDACTED : walk(child);
      }
      return out;
    } finally {
      ancestors.delete(v);
    }
  };

  return walk(value);
}
