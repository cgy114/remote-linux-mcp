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
