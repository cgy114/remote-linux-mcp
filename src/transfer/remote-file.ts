import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import type { TransferRunFacts } from '../audit/transfer-audit.js';
import { UsageError } from '../errors/classes.js';
import {
  BUILTIN_REMOTE_DENY_READ,
  BUILTIN_REMOTE_DENY_WRITE,
  assertRemoteRealpath,
  expandRemotePath,
  normalizeRemotePath,
  renderRemoteShellPath,
} from '../policy/remote-path.js';
import type { RunResult, ToolError } from '../types.js';
import { createCleanupTracker } from './cleanup.js';
import { runRemoteCommand, type TransferDeps } from './deps.js';
import { classifyTransportRun, internalFailure, policyFailure } from './errors.js';
import { assertFileSize } from './file-policy.js';
import { newLocalTempPath } from './local-path.js';
import { probeRemotePath, resolveRemoteHome } from './probe.js';
import { chmodStep, putStep, runSftpBatch } from './sftp.js';
import { newRemoteTempPath, swapRemoteIntoPlace } from './stage.js';
import { verifyRemoteFile } from './verify.js';
import { runFacts, sftpFailure, transferErrorToToolError } from './single-file.js';

export interface ReadFacts {
  ok: boolean;
  failure?: ToolError;
  /** 展开 $HOME 后的远端绝对路径。 */
  path: string;
  /** 整个远端文件的大小（不是返回内容的大小）。 */
  size: number;
  sha256?: string;
  mode?: number;
  /** utf8 表示返回内容是合法 UTF-8 且不含 NUL；否则为 base64。 */
  encoding: 'utf8' | 'base64';
  content: Buffer;
  returnedBytes: number;
  /** 返回内容是否只是文件的一部分（tail_lines / max_bytes）。 */
  truncated: boolean;
  durationMs: number;
  run?: TransferRunFacts;
}

export interface WriteFacts {
  ok: boolean;
  failure?: ToolError;
  path: string;
  bytes: number;
  sha256?: string;
  encoding: 'utf8' | 'base64';
  mode?: number;
  verified: boolean;
  atomicReplace: boolean;
  overwritten: boolean;
  durationMs: number;
  run?: TransferRunFacts;
  backupPath?: string;
}

const READ_MAX_OUTPUT_OVERHEAD = 64 * 1024;

function readFailure(
  base: { path: string; startedAt: number },
  failure: ToolError,
  run?: RunResult,
): ReadFacts {
  return {
    ok: false,
    failure,
    path: base.path,
    size: 0,
    encoding: 'utf8',
    content: Buffer.alloc(0),
    returnedBytes: 0,
    truncated: false,
    durationMs: Date.now() - base.startedAt,
    ...(run !== undefined ? { run: runFacts(run) } : {}),
  };
}

function writeFailure(
  base: { path: string; encoding: 'utf8' | 'base64'; startedAt: number },
  failure: ToolError,
  run?: RunResult,
): WriteFacts {
  return {
    ok: false,
    failure,
    path: base.path,
    bytes: 0,
    encoding: base.encoding,
    verified: false,
    atomicReplace: false,
    overwritten: false,
    durationMs: Date.now() - base.startedAt,
    ...(run !== undefined ? { run: runFacts(run) } : {}),
  };
}

function decodeBase64Strict(text: string): Buffer {
  if (text.length === 0) return Buffer.alloc(0);
  if (text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    throw new UsageError('remote read returned invalid base64', {
      code: 'remote_read_invalid_base64',
    });
  }
  const buf = Buffer.from(text, 'base64');
  if (buf.toString('base64') !== text) {
    throw new UsageError('remote read returned non-canonical base64', {
      code: 'remote_read_invalid_base64',
    });
  }
  return buf;
}

/** 是否为可安全按文本返回的内容：合法 UTF-8 且不含 NUL。 */
function isTextContent(buf: Buffer): boolean {
  if (buf.includes(0)) return false;
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(buf);
    return true;
  } catch {
    return false;
  }
}

function buildReadCommand(
  absolute: string,
  size: number | undefined,
  maxBytes: number,
  tailLines: number | undefined,
): string {
  const rendered = renderRemoteShellPath(absolute);
  let reader: string;
  if (tailLines !== undefined) {
    reader = `tail -n ${String(tailLines)} -- ${rendered}`;
  } else if ((size ?? 0) > maxBytes) {
    reader = `head -c ${String(maxBytes)} -- ${rendered}`;
  } else {
    reader = `cat -- ${rendered}`;
  }
  // 统一再截断一次：tail 的输出也可能超过 max_bytes。
  return `${reader} | head -c ${String(maxBytes)} | base64 | tr -d '\\n'`;
}

export interface ReadRemoteFileInput {
  deps: TransferDeps;
  remote: string;
  /** 返回内容的最大字节数（不是文件大小上限）。 */
  maxBytes: number;
  tailLines?: number;
  denyRead?: readonly string[];
  timeoutMs?: number;
}

/**
 * 读取远端文件：probe(hash+realpath) -> 类型/size 门禁 -> deny ->
 * 远端 tail/head -> base64 -> 解码 -> UTF-8 判定（否则 base64）。
 * 返回整文件 sha256/size 与本次返回字节数。失败以 facts 返回，不抛出。
 */
export async function readRemoteFile(input: ReadRemoteFileInput): Promise<ReadFacts> {
  const { deps } = input;
  const startedAt = Date.now();
  const base = { path: input.remote, startedAt };
  const denyRead = input.denyRead ?? BUILTIN_REMOTE_DENY_READ;
  let lastRun: RunResult | undefined;

  try {
    if (!Number.isSafeInteger(input.maxBytes) || input.maxBytes <= 0) {
      throw new UsageError('max_bytes must be a positive integer', { code: 'max_bytes_invalid' });
    }
    if (
      input.tailLines !== undefined &&
      (!Number.isSafeInteger(input.tailLines) || input.tailLines <= 0)
    ) {
      throw new UsageError('tail_lines must be a positive integer', {
        code: 'tail_lines_invalid',
      });
    }

    const home = deps.home ?? (await resolveRemoteHome(deps));
    const normalized = normalizeRemotePath(input.remote, deps.target.host.cwd);
    const absolute = expandRemotePath(normalized.absolute, home);
    base.path = absolute;

    const probe = await probeRemotePath(deps, absolute, { hash: true, realpath: true });
    if (!probe.ok) return readFailure(base, probe.error);
    const facts = probe.facts;
    if (!facts.exists) {
      return readFailure(
        base,
        policyFailure('remote_source_not_found', 'remote file does not exist'),
      );
    }
    if (facts.type === 'symlink') {
      return readFailure(
        base,
        policyFailure('remote_symlink', 'remote file is a symbolic link; symlinks are not followed'),
      );
    }
    if (facts.type !== 'file') {
      return readFailure(base, policyFailure('remote_invalid_type', 'remote path is not a regular file'));
    }
    assertFileSize(facts.size ?? 0, deps.limits, 'remote file');
    assertRemoteRealpath(facts.realpath ?? absolute, normalized.absolute, 'read', denyRead, home);
    if (facts.sha256 === undefined) {
      return readFailure(
        base,
        internalFailure('remote_hash_unavailable', 'remote sha256 could not be computed'),
      );
    }

    const command = buildReadCommand(absolute, facts.size, input.maxBytes, input.tailLines);
    const maxOutputBytes = Math.max(
      deps.target.config.defaults.maxOutputBytes,
      Math.ceil((input.maxBytes * 4) / 3) + READ_MAX_OUTPUT_OVERHEAD,
    );
    const run = await runRemoteCommandRead(deps, command, maxOutputBytes, input.timeoutMs);
    lastRun = run;
    const failure = classifyTransportRun(run, { label: 'remote read' });
    if (failure !== undefined) return readFailure(base, failure, run);

    const content = decodeBase64Strict(run.stdout.replace(/\s+/g, ''));
    const encoding: 'utf8' | 'base64' = isTextContent(content) ? 'utf8' : 'base64';
    const returnedBytes = content.length;
    return {
      ok: true,
      path: absolute,
      size: facts.size ?? 0,
      ...(facts.mode !== undefined ? { mode: facts.mode } : {}),
      sha256: facts.sha256,
      encoding,
      content,
      returnedBytes,
      truncated: returnedBytes < (facts.size ?? 0),
      durationMs: Date.now() - startedAt,
      ...(lastRun !== undefined ? { run: runFacts(lastRun) } : {}),
    };
  } catch (err) {
    return readFailure(base, transferErrorToToolError(err), lastRun);
  }
}

/** runRemoteCommand 的薄包装，隔离 label 与输出上限。 */
async function runRemoteCommandRead(
  deps: TransferDeps,
  command: string,
  maxOutputBytes: number,
  timeoutMs: number | undefined,
): Promise<RunResult> {
  return runRemoteCommand(deps, command, {
    maxOutputBytes,
    ...(timeoutMs !== undefined ? { timeoutMs } : {}),
    label: `read:${deps.target.host.alias}`,
  });
}

export interface WriteRemoteFileInput {
  deps: TransferDeps;
  remote: string;
  content: Buffer;
  encoding: 'utf8' | 'base64';
  /** 000–777；未提供时保留旧 mode，再退化为 0644。 */
  mode?: number;
  overwrite: boolean;
  denyWrite?: readonly string[];
  timeoutMs?: number;
}

function normalizeMode(mode: number): number {
  if (!Number.isSafeInteger(mode) || mode < 0) {
    throw new UsageError('mode must be a non-negative integer', { code: 'mode_invalid' });
  }
  return mode & 0o777;
}

/**
 * 写入远端文件：解码/限额 -> probe 门禁 -> 本地 0600 临时 -> sftp put 到远端临时 ->
 * verify(sha256+size) -> chmod(mode ?? 旧 mode ?? 0644) -> 原子换入 -> 清理两端临时。
 */
export async function writeRemoteFile(input: WriteRemoteFileInput): Promise<WriteFacts> {
  const { deps, overwrite } = input;
  const startedAt = Date.now();
  const base = { path: input.remote, encoding: input.encoding, startedAt };
  const denyWrite = input.denyWrite ?? BUILTIN_REMOTE_DENY_WRITE;
  const cleanup = createCleanupTracker({ deps });
  let lastRun: RunResult | undefined;
  let backupPath: string | undefined;

  try {
    if (!Buffer.isBuffer(input.content)) {
      throw new UsageError('content must be a Buffer', { code: 'content_invalid' });
    }
    assertFileSize(input.content.length, deps.limits, 'content');
    const sha256 = createHash('sha256').update(input.content).digest('hex');

    const home = deps.home ?? (await resolveRemoteHome(deps));
    const normalized = normalizeRemotePath(input.remote, deps.target.host.cwd);
    const absolute = expandRemotePath(normalized.absolute, home);
    base.path = absolute;

    const probe = await probeRemotePath(deps, absolute, { hash: false, realpath: true });
    if (!probe.ok) return writeFailure(base, probe.error);
    const facts = probe.facts;
    if (facts.exists) {
      if (facts.type === 'symlink') {
        return writeFailure(
          base,
          policyFailure('remote_symlink', 'remote target is a symbolic link'),
        );
      }
      if (facts.type !== 'file') {
        return writeFailure(
          base,
          policyFailure('remote_invalid_type', 'remote target is not a regular file'),
        );
      }
      if (!overwrite) {
        return writeFailure(
          base,
          policyFailure('target_exists', 'remote target already exists (overwrite is false)'),
        );
      }
    }
    assertRemoteRealpath(facts.realpath ?? absolute, normalized.absolute, 'write', denyWrite, home);

    const mode = normalizeMode(input.mode ?? facts.mode ?? 0o644);

    const localTemp = newLocalTempPath(os.tmpdir(), 'write');
    cleanup.addLocal(localTemp);
    await fs.writeFile(localTemp, input.content, { mode: 0o600 });

    const remoteTemp = newRemoteTempPath(absolute);
    const tempHandle = cleanup.addRemote(remoteTemp);

    const putRun = await runSftpBatch(deps, [putStep(localTemp, remoteTemp)], {
      ...(input.timeoutMs !== undefined ? { timeoutMs: input.timeoutMs } : {}),
      label: `write:${deps.target.host.alias}`,
    });
    lastRun = putRun;
    const putFailure = sftpFailure(putRun, 'sftp write');
    if (putFailure !== undefined) return writeFailure(base, putFailure, putRun);

    const verify = await verifyRemoteFile(deps, {
      path: remoteTemp,
      sha256,
      bytes: input.content.length,
    });
    if (verify !== undefined) return writeFailure(base, verify, putRun);

    const chmodRun = await runSftpBatch(deps, [chmodStep(mode, remoteTemp)], {
      ...(input.timeoutMs !== undefined ? { timeoutMs: input.timeoutMs } : {}),
      label: `write-chmod:${deps.target.host.alias}`,
    });
    lastRun = chmodRun;
    const chmodFailure = sftpFailure(chmodRun, 'sftp chmod');
    if (chmodFailure !== undefined) return writeFailure(base, chmodFailure, chmodRun);

    const swap = await swapRemoteIntoPlace(deps, { staged: remoteTemp, target: absolute });
    if (!swap.ok) {
      if (swap.rolledBack === false && facts.exists) backupPath = swap.backup;
      const error = swap.error ?? internalFailure('swap_failed', 'atomic replace failed');
      const failure =
        backupPath !== undefined
          ? { ...error, details: { ...(error.details ?? {}), backupPath } }
          : error;
      return writeFailure(base, failure, swap.run);
    }
    cleanup.release(tempHandle);
    if (facts.exists) cleanup.addRemote(swap.backup);

    return {
      ok: true,
      path: absolute,
      bytes: input.content.length,
      sha256,
      encoding: input.encoding,
      mode,
      verified: true,
      atomicReplace: true,
      overwritten: facts.exists,
      durationMs: Date.now() - startedAt,
      ...(lastRun !== undefined ? { run: runFacts(lastRun) } : {}),
    };
  } catch (err) {
    return writeFailure(base, transferErrorToToolError(err), lastRun);
  } finally {
    const report = await cleanup.run();
    if (report.failures.length > 0) {
      deps.ctx.log.warn(
        { failures: report.failures, tool: 'writeRemoteFile' },
        'transfer cleanup incomplete',
      );
    }
  }
}
