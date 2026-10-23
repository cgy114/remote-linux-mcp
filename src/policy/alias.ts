import { UsageError } from '../errors/classes.js';
import type { Alias } from '../types.js';

const ALIAS_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const RESERVED_ALIASES: ReadonlySet<string> = new Set(['default', 'serve', 'trust']);

/** 构造带机器可读 code 的 UsageError（target.ts 的集中构造入口）。 */
export function usageError(
  code: string,
  message: string,
  options?: { cause?: unknown },
): UsageError {
  return new UsageError(message, { ...options, code });
}

export function assertAlias(v: unknown): Alias {
  if (typeof v !== 'string') {
    throw usageError('invalid_alias', 'alias must be a string');
  }
  if (!ALIAS_RE.test(v)) {
    throw usageError('invalid_alias', `invalid alias ${JSON.stringify(v)} (must match ${ALIAS_RE.source})`);
  }
  if (RESERVED_ALIASES.has(v)) {
    throw usageError('invalid_alias', `alias ${JSON.stringify(v)} is reserved`);
  }
  return v as Alias;
}
