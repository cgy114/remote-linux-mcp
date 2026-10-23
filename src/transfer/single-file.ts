import { promises as fs } from 'node:fs';
import path from 'node:path';
import type { TransferRunFacts } from '../audit/transfer-audit.js';
import { ConfigError, UsageError } from '../errors/classes.js';
import { makeToolError } from '../errors/taxonomy.js';
import {
  BUILTIN_REMOTE_DENY_READ,
  BUILTIN_REMOTE_DENY_WRITE,
  assertRemoteRealpath,
  expandRemotePath,
  normalizeRemotePath,
} from '../policy/remote-path.js';
import type { RunResult, ToolError } from '../types.js';
import { hashLocalFile } from './checksum.js';
import { createCleanupTracker } from './cleanup.js';
import type { TransferDeps } from './deps.js';
import { classifyTransportRun, internalFailure, policyFailure } from './errors.js';
import { assertFileSize } from './file-policy.js';
import { newLocalTempPath, type LocalSource, type LocalTarget } from './local-path.js';
import { probeRemotePath, resolveRemoteHome, type RemotePathFacts } from './probe.js';
import { chmodStep, getStep, putStep, runSftpBatch, sftpDiagnostics } from './sftp.js';
import { newRemoteTempPath, swapRemoteIntoPlace } from './stage.js';
import { verifyLocalFile, verifyRemoteFile } from './verify.js';

export type TransferDirection = 'upload' | 'download';
export type TransferKind = 'file' | 'directory';

/**
 * 单文件/目录传输的事实结果。任何失败都以 ok=false + failure 返回，绝不抛出。
 * run 只包含最后一跳传输命令的退出事实（不含 stdout/stderr 内容）。
 */
export interface TransferFacts {
  ok: boolean;
  failure?: ToolError;
  direction: TransferDirection;
  kind: TransferKind;
  /** 本地源或本地目标（绝对路径）。 */
  sourcePath: string;
  /** 远端目标或远端源（展开 $HOME 后的绝对路径）。 */
  targetPath: string;
  files: number;
  bytes: number;
  sha256?: string;
  manifestDigest?: string;
  verified: boolean;
  atomicReplace: boolean;
  overwritten: boolean;
  durationMs: number;
  run?: TransferRunFacts;
  /** 提交失败且回滚失败时，原内容留在该备份路径（不会被清理）。 */
  backupPath?: string;
}

interface FactsBase {
  direction: TransferDirection;
  kind: TransferKind;
  sourcePath: string;
  targetPath: string;
  startedAt: number;
}

function failureFacts(base: FactsBase, failure: ToolError, run?: RunResult): TransferFacts {
  return {
    ok: false,
    failure,
    direction: base.direction,
    kind: base.kind,
    sourcePath: base.sourcePath,
    targetPath: base.targetPath,
    files: 0,
    bytes: 0,
    verified: false,
    atomicReplace: false,
    overwritten: false,
    durationMs: Date.now() - base.startedAt,
    ...(run !== undefined ? { run: runFacts(run) } : {}),
  };
}

/** UsageError/ConfigError -> Policy；其余 -> Internal。 */
export function transferErrorToToolError(err: unknown): ToolError {
  if (err instanceof UsageError) {
    return makeToolError('Policy', {
      code: typeof err.code === 'string' && err.code !== '' ? err.code : 'policy_denied',
      message: err.message,
    });
  }
  if (err instanceof ConfigError) {
    return makeToolError('Policy', { code: `config_${err.code}`, message: err.message });
  }
  return internalFailure(
    'transfer_internal_error',
    err instanceof Error ? err.message : String(err),
  );
}

/** RunResult -> 审计用退出事实（只保留摘要）。 */
export function runFacts(run: RunResult): TransferRunFacts {
  return {
    exitCode: run.exitCode,
    signal: run.signal,
    timedOut: run.timedOut,
    ...(run.spawnError !== undefined ? { spawnError: true } : {}),
    ...(run.ioError !== undefined ? { ioError: true } : {}),
    durationMs: run.durationMs,
    stdoutBytes: run.stdoutBytes,
    stderrBytes: run.stderrBytes,
  };
}

/** sftp 运行事实 -> ToolError；附带诊断摘要（不含文件内容）。 */
export function sftpFailure(run: RunResult, label: string): ToolError | undefined {
  const failure = classifyTransportRun(run, { label });
  if (failure === undefined) return undefined;
  const diagnostics = sftpDiagnostics(run);
  if (diagnostics.length > 0) {
    failure.details = { ...(failure.details ?? {}), diagnostics };
  }
  return failure;
}

interface RemoteFileContext {
  /** 展开 $HOME 后的绝对路径。 */
  absolute: string;
  home: string;
  facts: RemotePathFacts;
}

type RemoteContextResult =
  | { ok: true; context: RemoteFileContext }
  | { ok: false; error: ToolError };

/** 解析 home -> 规范化/展开路径 -> 探测类型/size/mode/realpath/hash。 */
async function inspectRemote(
  deps: TransferDeps,
  remote: string,
  opts: { hash?: boolean },
): Promise<RemoteContextResult> {
  const home = deps.home ?? (await resolveRemoteHome(deps));
  const normalized = normalizeRemotePath(remote, deps.target.host.cwd);
  const absolute = expandRemotePath(normalized.absolute, home);
  const probe = await probeRemotePath(deps, absolute, {
    hash: opts.hash === true,
    realpath: true,
  });
  if (!probe.ok) return { ok: false, error: probe.error };
  return {
    ok: true,
    context: { absolute, home, facts: probe.facts },
  };
}

function requirePlainTarget(
  facts: RemotePathFacts,
  overwrite: boolean,
  access: 'source' | 'target',
): ToolError | undefined {
  if (facts.type === 'symlink') {
    return policyFailure(
      'remote_symlink',
      `remote ${access} is a symbolic link; symlinks are not followed`,
    );
  }
  if (!facts.exists) return undefined;
  if (facts.type !== 'file') {
    return policyFailure('remote_invalid_type', `remote ${access} is not a regular file`);
  }
  if (access === 'target' && !overwrite) {
    return policyFailure('target_exists', 'remote target already exists (overwrite is false)');
  }
  return undefined;
}

export interface UploadSingleFileInput {
  deps: TransferDeps;
  local: LocalSource;
  remote: string;
  overwrite: boolean;
  /** 远端写 deny 列表；默认内置写 deny。 */
  denyWrite?: readonly string[];
  timeoutMs?: number;
}

/**
 * 单文件上传：probe(realpath) -> 类型/覆盖门禁 -> realpath deny ->
 * 本地流式 sha256 -> 同目录远端临时文件 -> sftp put+chmod ->
 * verify(sha256+size+mode) -> 原子换入 -> 清理临时文件。
 */
export async function uploadSingleFile(input: UploadSingleFileInput): Promise<TransferFacts> {
  const { deps, local, overwrite } = input;
  const base: FactsBase = {
    direction: 'upload',
    kind: 'file',
    sourcePath: local.path,
    targetPath: input.remote,
    startedAt: Date.now(),
  };
  const cleanup = createCleanupTracker({ deps });
  const denyWrite = input.denyWrite ?? BUILTIN_REMOTE_DENY_WRITE;
  let lastRun: RunResult | undefined;
  let backupPath: string | undefined;

  try {
    const inspected = await inspectRemote(deps, input.remote, { hash: false });
    if (!inspected.ok) return failureFacts(base, inspected.error);
    const { absolute, home, facts } = inspected.context;
    base.targetPath = absolute;

    const gate = requirePlainTarget(facts, overwrite, 'target');
    if (gate !== undefined) return failureFacts(base, gate);

    const original = normalizeRemotePath(input.remote, deps.target.host.cwd).absolute;
    assertRemoteRealpath(
      facts.realpath ?? absolute,
      original,
      'write',
      denyWrite,
      home,
    );

    const hash = await hashLocalFile(local.realPath);
    assertFileSize(hash.bytes, deps.limits, 'local source');

    const temp = newRemoteTempPath(absolute);
    const tempHandle = cleanup.addRemote(temp);
    const mode = local.mode & 0o777;

    const putRun = await runSftpBatch(
      deps,
      [putStep(local.realPath, temp), chmodStep(mode, temp)],
      {
        ...(input.timeoutMs !== undefined ? { timeoutMs: input.timeoutMs } : {}),
        label: `upload:${deps.target.host.alias}`,
      },
    );
    lastRun = putRun;
    const putFailure = sftpFailure(putRun, 'sftp upload');
    if (putFailure !== undefined) return failureFacts(base, putFailure, putRun);

    const verifyFailure = await verifyRemoteFile(deps, {
      path: temp,
      sha256: hash.sha256,
      bytes: hash.bytes,
      mode,
    });
    if (verifyFailure !== undefined) return failureFacts(base, verifyFailure, putRun);

    const swap = await swapRemoteIntoPlace(deps, { staged: temp, target: absolute });
    if (!swap.ok) {
      if (swap.rolledBack === false && facts.exists) backupPath = swap.backup;
      const error = swap.error ?? internalFailure('swap_failed', 'atomic replace failed');
      const failure = backupPath !== undefined
        ? { ...error, details: { ...(error.details ?? {}), backupPath } }
        : error;
      return failureFacts(base, failure, swap.run);
    }

    cleanup.release(tempHandle);
    if (facts.exists) cleanup.addRemote(swap.backup);

    return {
      ok: true,
      direction: 'upload',
      kind: 'file',
      sourcePath: local.path,
      targetPath: absolute,
      files: 1,
      bytes: hash.bytes,
      sha256: hash.sha256,
      verified: true,
      atomicReplace: true,
      overwritten: facts.exists,
      durationMs: Date.now() - base.startedAt,
      ...(lastRun !== undefined ? { run: runFacts(lastRun) } : {}),
    };
  } catch (err) {
    return failureFacts(base, transferErrorToToolError(err), lastRun);
  } finally {
    const report = await cleanup.run();
    if (report.failures.length > 0) {
      deps.ctx.log.warn(
        { failures: report.failures, tool: 'uploadSingleFile' },
        'transfer cleanup incomplete',
      );
    }
  }
}

export interface DownloadSingleFileInput {
  deps: TransferDeps;
  remote: string;
  localTarget: LocalTarget;
  overwrite: boolean;
  denyRead?: readonly string[];
  timeoutMs?: number;
}

interface LocalTargetState {
  exists: boolean;
  isFile: boolean;
  isSymlink: boolean;
  isDirectory: boolean;
}

async function inspectLocalTarget(target: string): Promise<LocalTargetState> {
  try {
    const stat = await fs.lstat(target);
    return {
      exists: true,
      isFile: stat.isFile(),
      isSymlink: stat.isSymbolicLink(),
      isDirectory: stat.isDirectory(),
    };
  } catch (err) {
    const code =
      typeof err === 'object' && err !== null && 'code' in err
        ? String((err as { code?: unknown }).code)
        : 'IO_ERROR';
    if (code === 'ENOENT') {
      return { exists: false, isFile: false, isSymlink: false, isDirectory: false };
    }
    throw new UsageError(`cannot stat local target: ${code}`, { code: 'local_io_error' });
  }
}

function localTargetGate(state: LocalTargetState, overwrite: boolean): ToolError | undefined {
  if (!state.exists) return undefined;
  if (state.isSymlink) {
    return policyFailure('local_symlink', 'local target is a symbolic link');
  }
  if (!state.isFile) {
    return policyFailure('local_invalid_type', 'local target is not a regular file');
  }
  if (!overwrite) {
    return policyFailure('target_exists', 'local target already exists (overwrite is false)');
  }
  return undefined;
}

async function replaceLocalFile(
  temp: string,
  target: string,
  backup: string,
): Promise<void> {
  await fs.rename(target, backup);
  try {
    await fs.rename(temp, target);
  } catch (err) {
    try {
      await fs.rename(backup, target);
      backup = '';
    } catch {
      // 回滚失败：保留备份，交由调用方标注路径。
    }
    if (backup !== '') {
      throw Object.assign(
        err instanceof Error ? err : new Error(String(err)),
        { backupPath: backup },
      );
    }
    throw err;
  }
  try {
    await fs.rm(backup, { force: true });
  } catch {
    // 备份残留不影响已完成的替换；由调用方的 cleanup 兜底。
  }
}

/**
 * 单文件下载：probe(存在/非 symlink/非 dir/hash+realpath) -> deny ->
 * 本地目标门禁 -> 同目录本地临时文件 -> sftp get -> verify(sha256+size) ->
 * （overwrite 时备份）rename -> 删除备份。失败回滚并清理。
 */
export async function downloadSingleFile(
  input: DownloadSingleFileInput,
): Promise<TransferFacts> {
  const { deps, overwrite, localTarget } = input;
  const base: FactsBase = {
    direction: 'download',
    kind: 'file',
    sourcePath: input.remote,
    targetPath: localTarget.path,
    startedAt: Date.now(),
  };
  const cleanup = createCleanupTracker({ deps });
  const denyRead = input.denyRead ?? BUILTIN_REMOTE_DENY_READ;
  let lastRun: RunResult | undefined;

  try {
    const inspected = await inspectRemote(deps, input.remote, { hash: true });
    if (!inspected.ok) return failureFacts(base, inspected.error);
    const { absolute, home, facts } = inspected.context;
    base.sourcePath = absolute;
    base.targetPath = localTarget.path;

    if (!facts.exists) {
      return failureFacts(
        base,
        policyFailure('remote_source_not_found', 'remote source does not exist'),
      );
    }
    if (facts.type === 'symlink') {
      return failureFacts(
        base,
        policyFailure('remote_symlink', 'remote source is a symbolic link; symlinks are not followed'),
      );
    }
    if (facts.type !== 'file') {
      return failureFacts(
        base,
        policyFailure('remote_invalid_type', 'remote source is not a regular file'),
      );
    }
    if (facts.size !== undefined) assertFileSize(facts.size, deps.limits, 'remote source');
    assertRemoteRealpath(
      facts.realpath ?? absolute,
      normalizeRemotePath(input.remote, deps.target.host.cwd).absolute,
      'read',
      denyRead,
      home,
    );
    if (facts.sha256 === undefined) {
      return failureFacts(
        base,
        internalFailure('remote_hash_unavailable', 'remote sha256 could not be computed'),
      );
    }

    const localState = await inspectLocalTarget(localTarget.path);
    const gate = localTargetGate(localState, overwrite);
    if (gate !== undefined) return failureFacts(base, gate);

    const dir = path.dirname(localTarget.path);
    const temp = newLocalTempPath(dir, 'download');
    cleanup.addLocal(temp);

    const getRun = await runSftpBatch(deps, [getStep(absolute, temp)], {
      ...(input.timeoutMs !== undefined ? { timeoutMs: input.timeoutMs } : {}),
      label: `download:${deps.target.host.alias}`,
    });
    lastRun = getRun;
    const getFailure = sftpFailure(getRun, 'sftp download');
    if (getFailure !== undefined) return failureFacts(base, getFailure, getRun);

    const verifyFailure = await verifyLocalFile(temp, {
      sha256: facts.sha256,
      bytes: facts.size,
    });
    if (verifyFailure !== undefined) return failureFacts(base, verifyFailure, getRun);

    // 校验期间目标可能刚出现：提交前按 overwrite 语义再判一次。
    const finalState = await inspectLocalTarget(localTarget.path);
    const finalGate = localTargetGate(finalState, overwrite);
    if (finalGate !== undefined) return failureFacts(base, finalGate, getRun);

    if (facts.mode !== undefined) {
      try {
        await fs.chmod(temp, facts.mode & 0o777);
      } catch {
        // Windows 等平台不支持完整权限位；内容校验才是关键。
      }
    }

    let backupPath: string | undefined;
    if (finalState.exists) {
      const backup = newLocalTempPath(dir, 'backup');
      try {
        await replaceLocalFile(temp, localTarget.path, backup);
      } catch (err) {
        const preserved =
          typeof err === 'object' && err !== null && 'backupPath' in err
            ? String((err as { backupPath?: unknown }).backupPath)
            : undefined;
        if (preserved !== undefined) backupPath = preserved;
        const error = transferErrorToToolError(err);
        const failure =
          backupPath !== undefined
            ? { ...error, details: { ...(error.details ?? {}), backupPath } }
            : error;
        return {
          ...failureFacts(base, failure, lastRun),
          ...(backupPath !== undefined ? { backupPath } : {}),
        };
      }
    } else {
      await fs.rename(temp, localTarget.path);
    }

    return {
      ok: true,
      direction: 'download',
      kind: 'file',
      sourcePath: absolute,
      targetPath: localTarget.path,
      files: 1,
      bytes: facts.size ?? 0,
      sha256: facts.sha256,
      verified: true,
      atomicReplace: true,
      overwritten: finalState.exists,
      durationMs: Date.now() - base.startedAt,
      ...(lastRun !== undefined ? { run: runFacts(lastRun) } : {}),
    };
  } catch (err) {
    return failureFacts(base, transferErrorToToolError(err), lastRun);
  } finally {
    const report = await cleanup.run();
    if (report.failures.length > 0) {
      deps.ctx.log.warn(
        { failures: report.failures, tool: 'downloadSingleFile' },
        'transfer cleanup incomplete',
      );
    }
  }
}
