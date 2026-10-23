import { randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';

/** 递归创建目录；已存在不报错。 */
export async function ensureDir(dir: string, mode = 0o700): Promise<void> {
  await fs.mkdir(dir, { recursive: true, mode });
}

/** 读取文本；文件不存在返回 undefined，其他错误抛出。 */
export async function readTextIfExists(file: string): Promise<string | undefined> {
  try {
    return await fs.readFile(file, 'utf8');
  } catch (err) {
    if (isErrnoCode(err, 'ENOENT')) return undefined;
    throw err;
  }
}

/**
 * 原子写入：同目录唯一临时文件 -> 写入 -> fsync -> close -> rename 覆盖目标。
 * 失败时清理临时文件；父目录自动创建。
 */
export async function atomicWriteFile(
  file: string,
  data: string,
  opts?: { mode?: number },
): Promise<void> {
  const dir = path.dirname(file);
  const base = path.basename(file);
  await ensureDir(dir);

  const tmp = path.join(dir, `.${base}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`);
  const mode = opts?.mode ?? 0o600;
  let handle: FileHandle | undefined;
  let renamed = false;
  try {
    handle = await fs.open(tmp, 'wx', mode);
    await handle.writeFile(data, 'utf8');
    await handle.sync();
    await handle.close();
    handle = undefined;
    await fs.rename(tmp, file);
    renamed = true;
  } finally {
    if (handle !== undefined) {
      await handle.close().catch(() => undefined);
    }
    if (!renamed) {
      await fs.rm(tmp, { force: true }).catch(() => undefined);
    }
  }
}

export function isErrnoCode(err: unknown, code: string): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: unknown }).code === code;
}
