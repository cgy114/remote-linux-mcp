import { UsageError } from '../errors/classes.js';
import type { FilesConfig } from '../types.js';

/** 传输域的四类限额（从 FilesConfig 抽取，便于纯函数复用）。 */
export interface FileLimits {
  maxFileBytes: number;
  maxFiles: number;
  maxTotalBytes: number;
  maxDepth: number;
}

export function fileLimitsFrom(files: FilesConfig): FileLimits {
  return {
    maxFileBytes: files.maxFileBytes,
    maxFiles: files.maxFiles,
    maxTotalBytes: files.maxTotalBytes,
    maxDepth: files.maxDepth,
  };
}

function limitError(code: string, message: string): UsageError {
  return new UsageError(message, { code });
}

/** 归档流（tar 写 stdout）允许的绝对上限：8 GiB。 */
export const ARCHIVE_STREAM_MAX_BYTES = 8 * 1024 * 1024 * 1024;

/** tar 对整棵树固定需要的头/块开销余量。 */
const ARCHIVE_OVERHEAD_BYTES = 64 * 1024 * 1024;

/** 每个条目的 tar 头/长文件名/填充开销余量。 */
const ARCHIVE_BYTES_PER_ENTRY = 1024;

/**
 * 目录归档流的上限：max_total_bytes + 每项 tar 开销 + 64 MiB 固定余量，
 * 并以 8 GiB 封顶。
 *
 * 归档体积不是文件内容之和：每个条目还有 512 字节头与块填充。用传输限额
 * 直接卡 stdout 会让稍大于 1 MiB 的目录归档被 `pumpToFile` 杀掉，因此归档
 * 管道必须使用这个独立上限。返回值始终是安全整数。
 */
export function archiveStreamLimit(
  limits: Pick<FileLimits, 'maxFiles' | 'maxTotalBytes'>,
): number {
  const total =
    Number.isSafeInteger(limits.maxTotalBytes) && limits.maxTotalBytes > 0
      ? limits.maxTotalBytes
      : 0;
  const files =
    Number.isSafeInteger(limits.maxFiles) && limits.maxFiles > 0 ? limits.maxFiles : 0;
  const sum = total + files * ARCHIVE_BYTES_PER_ENTRY + ARCHIVE_OVERHEAD_BYTES;
  return Number.isSafeInteger(sum)
    ? Math.min(sum, ARCHIVE_STREAM_MAX_BYTES)
    : ARCHIVE_STREAM_MAX_BYTES;
}

/** 单文件字节数超限。 */
export function assertFileSize(bytes: number, limits: FileLimits, label?: string): void {
  if (!Number.isSafeInteger(bytes) || bytes < 0) {
    throw limitError('file_size_invalid', 'file size must be a non-negative integer');
  }
  if (bytes > limits.maxFileBytes) {
    throw limitError(
      'file_too_large',
      `${label ?? 'file'} is ${bytes} bytes, exceeding max_file_bytes=${limits.maxFileBytes}`,
    );
  }
}

/** 文件/条目数量超限。 */
export function assertFileCount(count: number, limits: FileLimits, label?: string): void {
  if (count > limits.maxFiles) {
    throw limitError(
      'too_many_files',
      `${label ?? 'transfer'} has ${count} entries, exceeding max_files=${limits.maxFiles}`,
    );
  }
}

/** 累计字节数超限。 */
export function assertTotalBytes(bytes: number, limits: FileLimits, label?: string): void {
  if (bytes > limits.maxTotalBytes) {
    throw limitError(
      'total_too_large',
      `${label ?? 'transfer'} is ${bytes} bytes, exceeding max_total_bytes=${limits.maxTotalBytes}`,
    );
  }
}

/** 目录深度超限（直接子项为 1）。 */
export function assertDepth(depth: number, limits: FileLimits, label?: string): void {
  if (depth > limits.maxDepth) {
    throw limitError(
      'depth_too_deep',
      `${label ?? 'path'} depth ${depth} exceeds max_depth=${limits.maxDepth}`,
    );
  }
}

/**
 * 文件传输开关：local_roots 为空表示本机不允许任何文件转移，
 * 一律以 transfer_disabled 拒绝（上传与下载都适用）。
 */
export function assertTransferEnabled(files: Pick<FilesConfig, 'localRoots'>): void {
  if (files.localRoots.length === 0) {
    throw new UsageError('file transfer is disabled (files.local_roots is empty)', {
      code: 'transfer_disabled',
    });
  }
}
