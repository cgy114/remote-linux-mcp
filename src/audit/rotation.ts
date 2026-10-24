import { promises as fs } from 'node:fs';
import type { Dirent } from 'node:fs';
import path from 'node:path';
import type { Logger } from '../types.js';

/** 归档文件名：audit-YYYY-MM-DD.jsonl，冲突时加 .N（audit-YYYY-MM-DD.1.jsonl）。 */
const ARCHIVE_RE = /^audit-(\d{4})-(\d{2})-(\d{2})(?:\.(\d+))?\.jsonl$/;
const DAY_MS = 24 * 60 * 60 * 1000;

export interface RotateAuditFileOptions {
  dir: string;
  /** 活动文件：文件名或绝对路径（默认 audit.jsonl）。 */
  activeFile: string;
  /** 假时钟注入。 */
  now: Date;
  /** 本次即将写入的整行字节数（一行永不拆分）。 */
  incomingBytes: number;
  maxBytes: number;
  /** false 时只按大小轮转。默认 true。 */
  dateRotate?: boolean;
  log: Logger;
}

function activePath(dir: string, activeFile: string): string {
  return path.isAbsolute(activeFile) ? activeFile : path.join(dir, activeFile);
}

/** UTC 日期键，避免本地时区让测试与轮转边界漂移。 */
function dateKey(date: Date): string {
  const y = date.getUTCFullYear();
  const m = String(date.getUTCMonth() + 1).padStart(2, '0');
  const d = String(date.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function warn(log: Logger, err: unknown, message: string, file: string): void {
  try {
    log.warn(
      { err: err instanceof Error ? err.message : String(err), file },
      message,
    );
  } catch {
    // 日志失败不影响主流程。
  }
}

async function archiveName(dir: string, date: string): Promise<string> {
  const base = path.join(dir, `audit-${date}.jsonl`);
  if (!(await exists(base))) return base;
  for (let n = 1; n < 10_000; n++) {
    const candidate = path.join(dir, `audit-${date}.${n}.jsonl`);
    if (!(await exists(candidate))) return candidate;
  }
  throw new Error('too many audit archives for one date');
}

async function exists(file: string): Promise<boolean> {
  try {
    await fs.stat(file);
    return true;
  } catch {
    return false;
  }
}

/**
 * 在追加整行之前决定是否把活动文件改名归档。触发条件：
 * - 活动文件非空且 size + incomingBytes > maxBytes（单条超阈值时仍整行写入）
 * - dateRotate 且活动文件的 mtime 日期与 now 不同
 *
 * 返回是否发生了轮转。任何失败只 warn，不抛；调用方继续追加到活动文件。
 */
export async function rotateAuditFile(options: RotateAuditFileOptions): Promise<boolean> {
  const { dir, log } = options;
  const file = activePath(dir, options.activeFile);

  let stat: Awaited<ReturnType<typeof fs.stat>>;
  try {
    stat = await fs.stat(file);
  } catch {
    // 首次写入或文件不存在：无需轮转。
    return false;
  }
  if (!stat.isFile() || stat.size === 0) return false;

  const bySize = stat.size + options.incomingBytes > options.maxBytes;
  const byDate =
    options.dateRotate !== false && dateKey(stat.mtime) !== dateKey(options.now);
  if (!bySize && !byDate) return false;

  try {
    const target = await archiveName(dir, dateKey(stat.mtime));
    await fs.rename(file, target);
    return true;
  } catch (err) {
    warn(log, err, 'audit rotation failed; keeping active file', file);
    return false;
  }
}

export interface PruneAuditArchivesOptions {
  dir: string;
  now: Date;
  retainDays: number;
  log: Logger;
}

/** 解析严格命名的归档日期；非法返回 undefined。 */
function archiveDate(name: string): Date | undefined {
  const match = ARCHIVE_RE.exec(name);
  if (match === null) return undefined;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    return undefined;
  }
  return date;
}

/**
 * 删除超过 retainDays 的归档。只处理严格匹配 audit-YYYY-MM-DD[.N].jsonl 的
 * 普通文件；不删除活动 audit.jsonl；不跟随符号链接。
 * 返回被删除的文件名。失败只 warn。
 */
export async function pruneAuditArchives(
  options: PruneAuditArchivesOptions,
): Promise<string[]> {
  const { dir, now, retainDays, log } = options;
  let entries: Dirent[];
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch (err) {
    if (!isErrnoCode(err, 'ENOENT')) {
      warn(log, err, 'audit archive scan failed', dir);
    }
    return [];
  }

  const deleted: string[] = [];
  const cutoffMs = now.getTime() - retainDays * DAY_MS;
  for (const entry of entries) {
    // dirent.isFile() 对符号链接为 false，因此不会跟随链接。
    if (!entry.isFile()) continue;
    const date = archiveDate(entry.name);
    if (date === undefined) continue;
    if (date.getTime() >= cutoffMs) continue;
    const target = path.join(dir, entry.name);
    try {
      await fs.unlink(target);
      deleted.push(entry.name);
    } catch (err) {
      warn(log, err, 'audit archive pruning failed', target);
    }
  }
  return deleted;
}

function isErrnoCode(err: unknown, code: string): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: unknown }).code === code;
}
