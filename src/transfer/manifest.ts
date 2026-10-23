import { createHash } from 'node:crypto';
import { UsageError } from '../errors/classes.js';

export type ManifestEntryType = 'file' | 'dir' | 'symlink';

/** 传输清单条目。path 为相对传输根的 POSIX 路径（根自身用 "."）。 */
export interface ManifestEntry {
  path: string;
  type: ManifestEntryType;
  size: number;
  /** 权限位，已掩码为 0o777。 */
  mode: number;
  sha256?: string;
  linkTarget?: string;
}

export interface ManifestChange {
  path: string;
  expected?: ManifestEntry;
  actual?: ManifestEntry;
  reasons: string[];
}

export interface ManifestDiff {
  missing: ManifestEntry[];
  extra: ManifestEntry[];
  changed: ManifestChange[];
  same: number;
}

const MANIFEST_VERSION = 'v1';
const SHA256_RE = /^[0-9a-f]{64}$/;
const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

function manifestError(message: string): UsageError {
  return new UsageError(message, { code: 'remote_manifest_failed' });
}

function normalizeManifestPath(raw: string): string {
  if (raw.length === 0) throw manifestError('manifest path must not be empty');
  if (/[\u0000\r\n]/.test(raw)) throw manifestError('manifest path must not contain NUL or newline');
  if (raw.startsWith('/')) throw manifestError('manifest path must be relative');
  if (raw === '.') return '.';
  const segments = raw.split('/');
  for (const segment of segments) {
    if (segment === '' || segment === '.' || segment === '..') {
      throw manifestError(`manifest path contains an invalid segment: ${JSON.stringify(raw)}`);
    }
  }
  return raw;
}

/** 校验并规范化一个清单条目（mode 掩码到 0o777、sha256 小写）。 */
export function normalizeManifestEntry(entry: ManifestEntry): ManifestEntry {
  if (entry.type !== 'file' && entry.type !== 'dir' && entry.type !== 'symlink') {
    throw manifestError(`invalid manifest entry type: ${String(entry.type)}`);
  }
  if (!Number.isSafeInteger(entry.size) || entry.size < 0) {
    throw manifestError('manifest entry size must be a non-negative integer');
  }
  if (!Number.isSafeInteger(entry.mode) || entry.mode < 0) {
    throw manifestError('manifest entry mode must be a non-negative integer');
  }
  const out: ManifestEntry = {
    path: normalizeManifestPath(entry.path),
    type: entry.type,
    size: entry.size,
    mode: entry.mode & 0o777,
  };
  if (entry.sha256 !== undefined) {
    const sha = entry.sha256.toLowerCase();
    if (!SHA256_RE.test(sha)) throw manifestError('manifest entry sha256 must be 64 hex characters');
    out.sha256 = sha;
  }
  if (entry.linkTarget !== undefined) {
    if (entry.linkTarget.includes('\u0000')) {
      throw manifestError('manifest link target must not contain NUL');
    }
    out.linkTarget = entry.linkTarget;
  }
  return out;
}

/** 按 path 的码点序排序（与 locale 无关，跨平台确定）。 */
export function sortManifestEntries(entries: readonly ManifestEntry[]): ManifestEntry[] {
  return [...entries].sort((a, b) => {
    if (a.path < b.path) return -1;
    if (a.path > b.path) return 1;
    if (a.type < b.type) return -1;
    if (a.type > b.type) return 1;
    return 0;
  });
}

function encodeField(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64');
}

function decodeField(value: string, field: string): string {
  if (!BASE64_RE.test(value) || value.length % 4 !== 0) {
    throw manifestError(`manifest field ${field} is not valid base64`);
  }
  const buf = Buffer.from(value, 'base64');
  if (buf.toString('base64') !== value) {
    throw manifestError(`manifest field ${field} is not valid base64`);
  }
  return buf.toString('utf8');
}

/** 单行清单：v1 + 6 个 base64 字段（path/type/size/mode/sha256/linkTarget）。 */
export function renderManifestLine(entry: ManifestEntry): string {
  const e = normalizeManifestEntry(entry);
  return [
    MANIFEST_VERSION,
    encodeField(e.path),
    encodeField(e.type),
    encodeField(String(e.size)),
    encodeField(String(e.mode)),
    encodeField(e.sha256 ?? ''),
    encodeField(e.linkTarget ?? ''),
  ].join('\t');
}

/** 解析清单文本；任何格式错误抛 remote_manifest_failed。返回按 path 排序的条目。 */
export function parseManifest(text: string): ManifestEntry[] {
  if (typeof text !== 'string') throw manifestError('manifest must be text');
  const entries: ManifestEntry[] = [];
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    if (line.trim() === '') continue;
    const fields = line.split('\t');
    if (fields.length !== 7 || fields[0] !== MANIFEST_VERSION) {
      throw manifestError('manifest line has an unexpected format');
    }
    const path = decodeField(fields[1]!, 'path');
    const type = decodeField(fields[2]!, 'type') as ManifestEntryType;
    const sizeText = decodeField(fields[3]!, 'size');
    const modeText = decodeField(fields[4]!, 'mode');
    const sha = decodeField(fields[5]!, 'sha256');
    const linkTarget = decodeField(fields[6]!, 'linkTarget');
    if (!/^\d+$/.test(sizeText) || !/^\d+$/.test(modeText)) {
      throw manifestError('manifest size/mode must be decimal integers');
    }
    const entry: ManifestEntry = {
      path,
      type,
      size: Number(sizeText),
      mode: Number(modeText),
    };
    if (sha !== '') entry.sha256 = sha;
    if (linkTarget !== '') entry.linkTarget = linkTarget;
    entries.push(normalizeManifestEntry(entry));
  }
  return sortManifestEntries(entries);
}

/** 清单摘要：排序后逐行渲染（含末尾换行）再 sha256。 */
export function digestManifest(entries: readonly ManifestEntry[]): string {
  const text = sortManifestEntries(entries)
    .map((entry) => renderManifestLine(entry))
    .join('\n');
  return createHash('sha256').update(text.length > 0 ? `${text}\n` : '', 'utf8').digest('hex');
}

function toMap(entries: readonly ManifestEntry[]): Map<string, ManifestEntry> {
  const map = new Map<string, ManifestEntry>();
  for (const entry of entries) map.set(entry.path, normalizeManifestEntry(entry));
  return map;
}

function compareEntry(expected: ManifestEntry, actual: ManifestEntry): string[] {
  const reasons: string[] = [];
  if (expected.type !== actual.type) reasons.push('type');
  // 目录 size 依赖文件系统，不参与比较。
  if (expected.type !== 'dir' && actual.type !== 'dir' && expected.size !== actual.size) {
    reasons.push('size');
  }
  if (expected.mode !== actual.mode) reasons.push('mode');
  if (expected.sha256 !== undefined && expected.sha256 !== actual.sha256) reasons.push('sha256');
  if (expected.linkTarget !== undefined && expected.linkTarget !== actual.linkTarget) {
    reasons.push('link_target');
  }
  return reasons;
}

/** 对比期望/实际清单；返回缺失、多余、变更与相同条目数。 */
export function diffManifests(
  expected: readonly ManifestEntry[],
  actual: readonly ManifestEntry[],
): ManifestDiff {
  const expectedMap = toMap(expected);
  const actualMap = toMap(actual);
  const missing: ManifestEntry[] = [];
  const extra: ManifestEntry[] = [];
  const changed: ManifestChange[] = [];
  let same = 0;

  for (const [path, exp] of expectedMap) {
    const act = actualMap.get(path);
    if (act === undefined) {
      missing.push(exp);
      continue;
    }
    const reasons = compareEntry(exp, act);
    if (reasons.length === 0) {
      same += 1;
    } else {
      changed.push({ path, expected: exp, actual: act, reasons });
    }
  }
  for (const [path, act] of actualMap) {
    if (!expectedMap.has(path)) extra.push(act);
  }

  return {
    missing: sortManifestEntries(missing),
    extra: sortManifestEntries(extra),
    changed: changed.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)),
    same,
  };
}
