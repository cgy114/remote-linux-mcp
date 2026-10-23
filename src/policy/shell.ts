import { UsageError } from '../errors/classes.js';

/** POSIX 单引号引用：把内嵌的 `'` 写成 `'\''`，其余字符原样保留。 */
export function shSingleQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/**
 * 检测孤立 UTF-16 surrogate（未成对的 D800-DBFF / DC00-DFFF）。
 * 优先使用 Node 24 的 String.prototype.isWellFormed；不可用时手写扫描。
 */
export function hasLoneSurrogate(value: string): boolean {
  const wellFormed = (value as { isWellFormed?: () => boolean }).isWellFormed;
  if (typeof wellFormed === 'function') {
    try {
      return !wellFormed.call(value);
    } catch {
      // 落到手写扫描
    }
  }
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = i + 1 < value.length ? value.charCodeAt(i + 1) : 0;
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return true;
    }
  }
  return false;
}

/** 文本包含 NUL 或孤立 surrogate 时抛带 code 的 UsageError。 */
export function assertSafeText(value: string, opts: { field: string; code: string }): void {
  if (value.includes('\u0000')) {
    throw new UsageError(`${opts.field} must not contain a NUL byte`, { code: opts.code });
  }
  if (hasLoneSurrogate(value)) {
    throw new UsageError(`${opts.field} must not contain lone UTF-16 surrogates`, { code: opts.code });
  }
}
