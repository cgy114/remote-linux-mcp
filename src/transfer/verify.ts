import { promises as fs } from 'node:fs';
import type { ToolError } from '../types.js';
import { hashLocalFile } from './checksum.js';
import type { TransferDeps } from './deps.js';
import { remoteFailure } from './errors.js';
import { probeRemotePath } from './probe.js';

/** 校验失败统一为 RemoteExit 类别，code 描述具体不一致。 */
export function verifyFailure(
  code: string,
  message: string,
  details?: Record<string, unknown>,
): ToolError {
  return remoteFailure(code, message, details);
}

export interface VerifyRemoteFileInput {
  path: string;
  sha256?: string;
  bytes?: number;
  mode?: number;
}

/** 校验远端单文件：存在性/类型/size/sha256/mode；undefined 表示通过。 */
export async function verifyRemoteFile(
  deps: TransferDeps,
  input: VerifyRemoteFileInput,
): Promise<ToolError | undefined> {
  const probe = await probeRemotePath(deps, input.path, {
    hash: input.sha256 !== undefined,
    realpath: false,
  });
  if (!probe.ok) return probe.error;
  const facts = probe.facts;
  if (!facts.exists) {
    return verifyFailure('verify_missing', 'remote file is missing after transfer');
  }
  if (facts.type !== 'file') {
    return verifyFailure('verify_type_mismatch', 'remote path is not a regular file', {
      type: facts.type,
    });
  }
  if (input.bytes !== undefined && facts.size !== input.bytes) {
    return verifyFailure('verify_size_mismatch', 'remote file size differs', {
      expectedBytes: input.bytes,
      actualBytes: facts.size,
    });
  }
  if (input.sha256 !== undefined) {
    if (facts.sha256 === undefined) {
      return verifyFailure('verify_sha256_unavailable', 'remote sha256 could not be computed');
    }
    if (facts.sha256 !== input.sha256.toLowerCase()) {
      return verifyFailure('verify_sha256_mismatch', 'remote file sha256 differs', {
        expectedSha256: input.sha256.toLowerCase(),
        actualSha256: facts.sha256,
      });
    }
  }
  if (input.mode !== undefined && facts.mode !== (input.mode & 0o777)) {
    return verifyFailure('verify_mode_mismatch', 'remote file mode differs', {
      expectedMode: input.mode & 0o777,
      actualMode: facts.mode,
    });
  }
  return undefined;
}

export interface VerifyLocalFileInput {
  sha256?: string;
  bytes?: number;
  mode?: number;
}

/** 校验本地单文件；undefined 表示通过。 */
export async function verifyLocalFile(
  file: string,
  input: VerifyLocalFileInput,
): Promise<ToolError | undefined> {
  let stat;
  try {
    stat = await fs.lstat(file);
  } catch {
    return verifyFailure('verify_missing', 'local file is missing after transfer');
  }
  if (!stat.isFile()) {
    return verifyFailure('verify_type_mismatch', 'local path is not a regular file');
  }
  if (input.bytes !== undefined && stat.size !== input.bytes) {
    return verifyFailure('verify_size_mismatch', 'local file size differs', {
      expectedBytes: input.bytes,
      actualBytes: stat.size,
    });
  }
  if (input.mode !== undefined && (stat.mode & 0o777) !== (input.mode & 0o777)) {
    return verifyFailure('verify_mode_mismatch', 'local file mode differs', {
      expectedMode: input.mode & 0o777,
      actualMode: stat.mode & 0o777,
    });
  }
  if (input.sha256 !== undefined) {
    let actual: string;
    try {
      actual = (await hashLocalFile(file)).sha256;
    } catch {
      return verifyFailure('verify_local_io', 'local file could not be read for verification');
    }
    if (actual !== input.sha256.toLowerCase()) {
      return verifyFailure('verify_sha256_mismatch', 'local file sha256 differs', {
        expectedSha256: input.sha256.toLowerCase(),
        actualSha256: actual,
      });
    }
  }
  return undefined;
}

