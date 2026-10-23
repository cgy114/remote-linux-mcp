import { promises as fs } from 'node:fs';
import path from 'node:path';
import { TrustError } from '../errors/classes.js';
import { ensureDir, isErrnoCode } from './fsx.js';

const POLL_MS = 50;
const JITTER_MS = 25;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * 基于 O_EXCL 的文件锁。
 * - 已存在则每 50ms（加抖动）轮询；超过 timeoutMs（默认 5000）抛 TrustError('lock_busy')。
 * - 锁文件 mtime 早于 staleMs（默认 30000）视为陈旧，删除后重试。
 * - finally 删除锁文件（ENOENT 忽略）。锁内容为 { pid, time }。
 */
export async function withFileLock<T>(
  file: string,
  fn: () => Promise<T>,
  opts?: { staleMs?: number; timeoutMs?: number },
): Promise<T> {
  const staleMs = opts?.staleMs ?? 30000;
  const timeoutMs = opts?.timeoutMs ?? 5000;
  const deadline = Date.now() + timeoutMs;

  await ensureDir(path.dirname(file));

  for (;;) {
    if (await tryAcquire(file)) break;

    if (await removeIfStale(file, staleMs)) continue;

    if (Date.now() >= deadline) {
      throw new TrustError('lock_busy', `无法获取锁（${timeoutMs}ms 超时）：${file}`);
    }
    await sleep(POLL_MS + Math.random() * JITTER_MS);
  }

  try {
    return await fn();
  } finally {
    await fs.unlink(file).catch((err: unknown) => {
      if (!isErrnoCode(err, 'ENOENT')) throw err;
    });
  }
}

async function tryAcquire(file: string): Promise<boolean> {
  let handle;
  try {
    handle = await fs.open(file, 'wx');
  } catch (err) {
    if (isErrnoCode(err, 'EEXIST')) return false;
    throw err;
  }
  try {
    await handle.writeFile(JSON.stringify({ pid: process.pid, time: new Date().toISOString() }), 'utf8');
  } catch (err) {
    await handle.close().catch(() => undefined);
    await fs.unlink(file).catch(() => undefined);
    throw err;
  }
  await handle.close();
  return true;
}

/** 若锁文件陈旧则删除并返回 true；锁不存在也返回 true（立即重试）。 */
async function removeIfStale(file: string, staleMs: number): Promise<boolean> {
  let mtimeMs: number;
  try {
    mtimeMs = (await fs.stat(file)).mtimeMs;
  } catch (err) {
    if (isErrnoCode(err, 'ENOENT')) return true;
    throw err;
  }
  if (Date.now() - mtimeMs <= staleMs) return false;
  try {
    await fs.unlink(file);
  } catch (err) {
    if (!isErrnoCode(err, 'ENOENT')) throw err;
  }
  return true;
}
