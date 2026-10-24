import { isSensitiveAuditKey, REDACTED, redactAuditText } from './audit/redact.js';
import type { LogLevel, Logger } from './types.js';

const LEVEL_RANK: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

const STACK_MAX_BYTES = 4096;

function parseLevel(raw: string | undefined): LogLevel {
  switch (raw?.toLowerCase()) {
    case 'debug':
    case 'info':
    case 'warn':
    case 'error':
      return raw.toLowerCase() as LogLevel;
    default:
      return 'info';
  }
}

/**
 * 递归脱敏。键名匹配内置正则或 keys 参数时替换为 [REDACTED]；
 * 字符串中的 ProxyCommand= 值被替换；循环引用返回 [Circular]。
 */
export function redact(value: unknown, keys: readonly string[] = []): unknown {
  const extra = new Set(keys.map((k) => k.toLowerCase()));
  const ancestors = new Set<object>();

  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') {
      // 与审计共用同一套模式（Bearer、provider key、password=、URL userinfo、ProxyCommand）。
      return redactAuditText(v);
    }
    if (v === null || typeof v !== 'object') {
      return v;
    }
    if (ancestors.has(v)) {
      return '[Circular]';
    }
    ancestors.add(v);
    try {
      if (Array.isArray(v)) {
        return v.map((item) => walk(item));
      }
      const out: Record<string, unknown> = {};
      for (const [k, child] of Object.entries(v)) {
        if (isSensitiveAuditKey(k) || extra.has(k.toLowerCase())) {
          out[k] = REDACTED;
        } else {
          out[k] = walk(child);
        }
      }
      return out;
    } finally {
      ancestors.delete(v);
    }
  };

  return walk(value);
}

function truncateStack(stack: string | undefined): string | undefined {
  if (stack === undefined) return undefined;
  const buf = Buffer.from(stack, 'utf8');
  if (buf.byteLength <= STACK_MAX_BYTES) return stack;
  return buf.subarray(0, STACK_MAX_BYTES).toString('utf8') + '...[truncated]';
}

/**
 * 序列化错误。stack 截断到 4KB；cause 递归一层（cause 自身的 cause 不再展开）；全部脱敏。
 */
export function serializeError(
  e: unknown,
): { name: string; message: string; code?: string; stack?: string; cause?: unknown } {
  if (!(e instanceof Error)) {
    return { name: 'NonError', message: typeof e === 'string' ? e : safeString(e) };
  }
  const err = e as Error & { code?: unknown };
  const out: { name: string; message: string; code?: string; stack?: string; cause?: unknown } = {
    name: err.name,
    message: err.message,
  };
  if (typeof err.code === 'string') out.code = err.code;
  const stack = truncateStack(err.stack);
  if (stack !== undefined) out.stack = stack;
  if (err.cause !== undefined) {
    // cause 只展开一层：用 shallow 形式，不再递归其 cause
    out.cause = serializeErrorShallow(err.cause);
  }
  return redact(out) as typeof out;
}

function serializeErrorShallow(e: unknown): unknown {
  if (!(e instanceof Error)) return e;
  const err = e as Error & { code?: unknown };
  const out: Record<string, unknown> = { name: err.name, message: err.message };
  if (typeof err.code === 'string') out.code = err.code;
  const stack = truncateStack(err.stack);
  if (stack !== undefined) out.stack = stack;
  return out;
}

function safeString(v: unknown): string {
  try {
    return JSON.stringify(v) ?? String(v);
  } catch {
    return String(v);
  }
}

interface LoggerState {
  level: LogLevel;
  stream: NodeJS.WritableStream;
}

function buildLogger(state: LoggerState, bindings: Record<string, unknown>): Logger {
  const emit = (lvl: LogLevel, b: Record<string, unknown> | string, msg?: string): void => {
    if (LEVEL_RANK[lvl] < LEVEL_RANK[state.level]) return;
    let fields: Record<string, unknown>;
    let text: string;
    if (typeof b === 'string') {
      fields = {};
      text = b;
    } else {
      fields = b;
      text = msg ?? '';
    }
    const record = redact({
      time: new Date().toISOString(),
      level: lvl,
      msg: text,
      ...bindings,
      ...fields,
    });
    let line: string;
    try {
      line = JSON.stringify(record);
    } catch {
      line = JSON.stringify({ time: new Date().toISOString(), level: lvl, msg: text, note: 'unserializable' });
    }
    state.stream.write(line + '\n');
  };

  return {
    debug: (b, msg) => emit('debug', b, msg),
    info: (b, msg) => emit('info', b, msg),
    warn: (b, msg) => emit('warn', b, msg),
    error: (b, msg) => emit('error', b, msg),
    child: (extra) => buildLogger(state, { ...bindings, ...extra }),
  };
}

/**
 * 创建 JSON 行日志。默认级别读取 REMOTE_MCP_LOG_LEVEL（缺省 info），默认写 process.stderr。
 * 绝不写 stdout（MCP stdio 协议占用 stdout）。
 */
export function createLogger(opts?: {
  level?: LogLevel;
  bindings?: Record<string, unknown>;
  stream?: NodeJS.WritableStream;
}): Logger {
  const state: LoggerState = {
    level: opts?.level ?? parseLevel(process.env['REMOTE_MCP_LOG_LEVEL']),
    stream: opts?.stream ?? process.stderr,
  };
  return buildLogger(state, opts?.bindings ?? {});
}

/** 合并 bindings 生成子 logger。 */
export function childLogger(parent: Logger, bindings: Record<string, unknown>): Logger {
  return parent.child(bindings);
}
