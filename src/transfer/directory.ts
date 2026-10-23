import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
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
import {
  assertFileCount,
  assertFileSize,
  assertTotalBytes,
} from './file-policy.js';
import {
  newLocalTempPath,
  buildLocalManifest,
  type LocalSource,
  type LocalTarget,
} from './local-path.js';
import {
  diffManifests,
  digestManifest,
  type ManifestDiff,
  type ManifestEntry,
} from './manifest.js';
import { probeRemoteManifest, probeRemotePath, resolveRemoteHome } from './probe.js';
import {
  createLocalArchive,
  runLocalTar,
  runRemoteTar,
  tarFailure,
} from './tar.js';
import { newRemoteTempPath, swapRemoteIntoPlace } from './stage.js';
import { verifyFailure } from './verify.js';
import {
  runFacts,
  transferErrorToToolError,
  type TransferFacts,
} from './single-file.js';

function emptyFailure(
  input: {
    direction: 'upload' | 'download';
    sourcePath: string;
    targetPath: string;
    startedAt: number;
  },
  failure: ToolError,
  run?: RunResult,
): TransferFacts {
  return {
    ok: false,
    failure,
    direction: input.direction,
    kind: 'directory',
    sourcePath: input.sourcePath,
    targetPath: input.targetPath,
    files: 0,
    bytes: 0,
    verified: false,
    atomicReplace: false,
    overwritten: false,
    durationMs: Date.now() - input.startedAt,
    ...(run !== undefined ? { run: runFacts(run) } : {}),
  };
}

function countFiles(entries: readonly ManifestEntry[]): { files: number; bytes: number } {
  let files = 0;
  let bytes = 0;
  for (const entry of entries) {
    if (entry.type === 'file') {
      files += 1;
      bytes += entry.size;
    }
  }
  return { files, bytes };
}

function manifestMismatch(
  diff: ManifestDiff,
  side: 'remote' | 'local',
): ToolError | undefined {
  if (diff.missing.length === 0 && diff.extra.length === 0 && diff.changed.length === 0) {
    return undefined;
  }
  const sample = [
    ...diff.missing.map((entry) => `missing:${entry.path}`),
    ...diff.extra.map((entry) => `extra:${entry.path}`),
    ...diff.changed.map((change) => `changed:${change.path}(${change.reasons.join(',')})`),
  ].slice(0, 10);
  return verifyFailure(
    'verify_manifest_mismatch',
    `${side} directory manifest differs after transfer`,
    {
      missing: diff.missing.length,
      extra: diff.extra.length,
      changed: diff.changed.length,
      sample,
    },
  );
}

/** mkdir 0700（staging 目录）；失败返回 ToolError。 */
async function createStagingDirectory(
  deps: TransferDeps,
  dir: string,
  timeoutMs: number | undefined,
): Promise<{ error?: ToolError; run: RunResult }> {
  // 远端 staging 目录要求 0700：mkdir -p 之后再 chmod（umask 不影响显式 chmod）。
  const rendered = renderRemoteShellPath(dir);
  const run = await runRemoteCommand(
    deps,
    `mkdir -p -- ${rendered} && chmod 700 -- ${rendered}`,
    {
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      label: `staging-mkdir:${deps.target.host.alias}`,
    },
  );
  const error = classifyTransportRun(run, { label: 'staging mkdir' });
  return error === undefined ? { run } : { run, error };
}

/** Windows 上没有有意义的 POSIX mode；本地侧比较时忽略 mode，其余维度照常比较。 */
function diffPortable(
  expected: readonly ManifestEntry[],
  actual: readonly ManifestEntry[],
): ManifestDiff {
  if (process.platform !== 'win32') return diffManifests(expected, actual);
  const actualByPath = new Map(actual.map((entry) => [entry.path, entry]));
  const adjusted = expected.map((entry) => {
    const match = actualByPath.get(entry.path);
    return match === undefined ? entry : { ...entry, mode: match.mode };
  });
  return diffManifests(adjusted, actual);
}

/**
 * 本地解包 tar。Windows 的 System32 bsdtar 会按 ANSI 代码页解释归档里的
 * UTF-8 文件名（中文变成乱码），因此优先使用 PATH 中 Git 的 GNU tar；
 * 找不到时退回系统 tar。POSIX 直接使用系统 tar。
 */
async function resolveLocalExtractTar(): Promise<string | undefined> {
  if (process.platform !== 'win32') return undefined;
  const dirs = (process.env.PATH ?? '').split(path.delimiter).filter((dir) => dir.length > 0);
  const candidates: string[] = [];
  for (const dir of dirs) {
    // Git Bash 环境通常直接提供 <Git>/usr/bin；PowerShell/npx 往往只有
    // <Git>/cmd，需要从安装根目录反推 GNU tar。
    if (/[\\/]Git[\\/]usr[\\/]bin[\\/]?$/i.test(dir)) {
      candidates.push(path.join(dir, 'tar.exe'));
    } else if (/[\\/]Git[\\/]cmd[\\/]?$/i.test(dir)) {
      candidates.push(path.join(dir, '..', 'usr', 'bin', 'tar.exe'));
    } else if (/[\\/]Git[\\/]mingw64[\\/]bin[\\/]?$/i.test(dir)) {
      candidates.push(path.join(dir, '..', '..', 'usr', 'bin', 'tar.exe'));
    }
  }
  for (const candidate of candidates) {
    try {
      await fs.access(candidate);
      return path.resolve(candidate);
    } catch {
      // 继续尝试下一个候选。
    }
  }
  return undefined;
}

/**
 * 上传侧的清单比较。Windows 上 Node 报告的目录 mode（如 0666）与 bsdtar
 * 归档/远端解包后的目录 mode（0777）没有可比性，因此只对目录忽略 mode；
 * 文件仍严格比较 type/size/mode/sha256。POSIX 上全部严格比较。
 */
function diffUploadManifest(
  expected: readonly ManifestEntry[],
  actual: readonly ManifestEntry[],
): ManifestDiff {
  if (process.platform !== 'win32') return diffManifests(expected, actual);
  const actualByPath = new Map(actual.map((entry) => [entry.path, entry]));
  const adjusted = expected.map((entry) => {
    if (entry.type !== 'dir') return entry;
    const match = actualByPath.get(entry.path);
    return match === undefined || match.type !== 'dir'
      ? entry
      : { ...entry, mode: match.mode };
  });
  return diffManifests(adjusted, actual);
}

export interface UploadTreeInput {
  deps: TransferDeps;
  local: LocalSource;
  /** prepare 阶段根据本地目录生成的清单（path 相对传输根）。 */
  manifest: readonly ManifestEntry[];
  remote: string;
  overwrite: boolean;
  denyWrite?: readonly string[];
  timeoutMs?: number;
}

/**
 * 目录上传：probe -> staging(0700) -> 本地 tar -> 远端 tar 解包（-p 保留权限） ->
 * staging manifest 与本地清单比对 -> 原子换入 -> 清理归档/staging。
 */
export async function uploadTree(input: UploadTreeInput): Promise<TransferFacts> {
  const { deps, local, overwrite, manifest } = input;
  const startedAt = Date.now();
  const base = {
    direction: 'upload' as const,
    sourcePath: local.path,
    targetPath: input.remote,
    startedAt,
  };
  const cleanup = createCleanupTracker({ deps });
  const denyWrite = input.denyWrite ?? BUILTIN_REMOTE_DENY_WRITE;
  let lastRun: RunResult | undefined;
  let backupPath: string | undefined;

  try {
    const home = deps.home ?? (await resolveRemoteHome(deps));
    const normalized = normalizeRemotePath(input.remote, deps.target.host.cwd);
    const absolute = expandRemotePath(normalized.absolute, home);
    base.targetPath = absolute;

    const probe = await probeRemotePath(deps, absolute, { hash: false, realpath: true });
    if (!probe.ok) return emptyFailure(base, probe.error);
    const facts = probe.facts;
    if (facts.exists) {
      if (facts.type === 'symlink') {
        return emptyFailure(
          base,
          policyFailure('remote_symlink', 'remote target is a symbolic link'),
        );
      }
      if (facts.type !== 'dir') {
        return emptyFailure(
          base,
          policyFailure('remote_invalid_type', 'remote target is not a directory'),
        );
      }
      if (!overwrite) {
        return emptyFailure(
          base,
          policyFailure('target_exists', 'remote target already exists (overwrite is false)'),
        );
      }
    }
    assertRemoteRealpath(
      facts.realpath ?? absolute,
      normalized.absolute,
      'write',
      denyWrite,
      home,
    );

    const staging = newRemoteTempPath(absolute);
    const stagingHandle = cleanup.addRemote(staging);
    const stagingResult = await createStagingDirectory(deps, staging, input.timeoutMs);
    lastRun = stagingResult.run;
    if (stagingResult.error !== undefined) {
      return emptyFailure(base, stagingResult.error, stagingResult.run);
    }

    const archive = newLocalTempPath(os.tmpdir(), 'upload-archive');
    cleanup.addLocal(archive);
    const createRun = await createLocalArchive({
      source: local.realPath,
      archive,
      contents: true,
      ...(input.timeoutMs !== undefined ? { timeoutMs: input.timeoutMs } : {}),
    });
    lastRun = createRun;
    const createFailure = tarFailure(createRun);
    if (createFailure !== undefined) return emptyFailure(base, createFailure, createRun);

    const extractCommand = `tar -C ${renderRemoteShellPath(staging)} -xpf -`;
    const extractRun = await runRemoteTar(deps, extractCommand, {
      stdinFile: archive,
      ...(input.timeoutMs !== undefined ? { timeoutMs: input.timeoutMs } : {}),
      label: `upload-extract:${deps.target.host.alias}`,
    });
    lastRun = extractRun;
    const extractFailure = tarFailure(extractRun);
    if (extractFailure !== undefined) return emptyFailure(base, extractFailure, extractRun);

    const staged = await probeRemoteManifest(deps, staging, {
      maxFiles: deps.limits.maxFiles,
      maxDepth: deps.limits.maxDepth,
    });
    if (!staged.ok) return emptyFailure(base, staged.error, extractRun);
    const diff = diffUploadManifest(manifest, staged.entries);
    const mismatch = manifestMismatch(diff, 'remote');
    if (mismatch !== undefined) return emptyFailure(base, mismatch, extractRun);

    const swap = await swapRemoteIntoPlace(deps, { staged: staging, target: absolute });
    if (!swap.ok) {
      if (swap.rolledBack === false && facts.exists) backupPath = swap.backup;
      const error = swap.error ?? internalFailure('swap_failed', 'atomic replace failed');
      const failure =
        backupPath !== undefined
          ? { ...error, details: { ...(error.details ?? {}), backupPath } }
          : error;
      return emptyFailure(base, failure, swap.run);
    }
    cleanup.release(stagingHandle);
    if (facts.exists) cleanup.addRemote(swap.backup);

    const { files, bytes } = countFiles(manifest);
    return {
      ok: true,
      direction: 'upload',
      kind: 'directory',
      sourcePath: local.path,
      targetPath: absolute,
      files,
      bytes,
      manifestDigest: digestManifest(manifest),
      verified: true,
      atomicReplace: true,
      overwritten: facts.exists,
      durationMs: Date.now() - startedAt,
      ...(lastRun !== undefined ? { run: runFacts(lastRun) } : {}),
    };
  } catch (err) {
    return emptyFailure(base, transferErrorToToolError(err), lastRun);
  } finally {
    const report = await cleanup.run();
    if (report.failures.length > 0) {
      deps.ctx.log.warn(
        { failures: report.failures, tool: 'uploadTree' },
        'transfer cleanup incomplete',
      );
    }
  }
}

export interface DownloadTreeInput {
  deps: TransferDeps;
  remote: string;
  localTarget: LocalTarget;
  overwrite: boolean;
  denyRead?: readonly string[];
  timeoutMs?: number;
}

interface LocalState {
  exists: boolean;
  isSymlink: boolean;
}

async function statLocal(target: string): Promise<LocalState> {
  try {
    const stat = await fs.lstat(target);
    return { exists: true, isSymlink: stat.isSymbolicLink() };
  } catch (err) {
    const code =
      typeof err === 'object' && err !== null && 'code' in err
        ? String((err as { code?: unknown }).code)
        : 'IO_ERROR';
    if (code === 'ENOENT') return { exists: false, isSymlink: false };
    throw new UsageError(`cannot stat local target: ${code}`, { code: 'local_io_error' });
  }
}

/**
 * 目录下载：probe 根目录 -> 远端 manifest（限额）-> 本地目标门禁 ->
 * 远端 tar -> 本地归档 -> 解包到同级 staging -> 本地 manifest 比对 ->
 * （overwrite 时备份）rename -> 删除备份。
 */
export async function downloadTree(input: DownloadTreeInput): Promise<TransferFacts> {
  const { deps, overwrite, localTarget } = input;
  const startedAt = Date.now();
  const base = {
    direction: 'download' as const,
    sourcePath: input.remote,
    targetPath: localTarget.path,
    startedAt,
  };
  const cleanup = createCleanupTracker({ deps });
  const denyRead = input.denyRead ?? BUILTIN_REMOTE_DENY_READ;
  let lastRun: RunResult | undefined;

  try {
    const home = deps.home ?? (await resolveRemoteHome(deps));
    const normalized = normalizeRemotePath(input.remote, deps.target.host.cwd);
    const absolute = expandRemotePath(normalized.absolute, home);
    base.sourcePath = absolute;

    const probe = await probeRemotePath(deps, absolute, { hash: false, realpath: true });
    if (!probe.ok) return emptyFailure(base, probe.error);
    const facts = probe.facts;
    if (!facts.exists) {
      return emptyFailure(
        base,
        policyFailure('remote_source_not_found', 'remote source does not exist'),
      );
    }
    if (facts.type === 'symlink') {
      return emptyFailure(
        base,
        policyFailure('remote_symlink', 'remote source is a symbolic link'),
      );
    }
    if (facts.type !== 'dir') {
      return emptyFailure(
        base,
        policyFailure('remote_invalid_type', 'remote source is not a directory'),
      );
    }
    assertRemoteRealpath(
      facts.realpath ?? absolute,
      normalized.absolute,
      'read',
      denyRead,
      home,
    );

    const manifestResult = await probeRemoteManifest(deps, absolute, {
      maxFiles: deps.limits.maxFiles,
      maxDepth: deps.limits.maxDepth,
      hash: true,
    });
    if (!manifestResult.ok) return emptyFailure(base, manifestResult.error);
    const sourceManifest = manifestResult.entries;
    assertFileCount(sourceManifest.length, deps.limits, 'remote tree');
    let totalBytes = 0;
    for (const entry of sourceManifest) {
      if (entry.type === 'file') {
        assertFileSize(entry.size, deps.limits, entry.path);
        totalBytes += entry.size;
      }
    }
    assertTotalBytes(totalBytes, deps.limits, 'remote tree');

    const localState = await statLocal(localTarget.path);
    if (localState.exists) {
      if (localState.isSymlink) {
        return emptyFailure(base, policyFailure('local_symlink', 'local target is a symbolic link'));
      }
      if (!overwrite) {
        return emptyFailure(
          base,
          policyFailure('target_exists', 'local target already exists (overwrite is false)'),
        );
      }
    }

    const archive = newLocalTempPath(os.tmpdir(), 'download-archive');
    cleanup.addLocal(archive);
    const createCommand = `tar -C ${renderRemoteShellPath(absolute)} -cf - .`;
    const createRun = await runRemoteTar(deps, createCommand, {
      stdoutFile: archive,
      ...(input.timeoutMs !== undefined ? { timeoutMs: input.timeoutMs } : {}),
      label: `download-tar:${deps.target.host.alias}`,
    });
    lastRun = createRun;
    const createFailure = tarFailure(createRun);
    if (createFailure !== undefined) return emptyFailure(base, createFailure, createRun);

    const dir = path.dirname(localTarget.path);
    const staging = newLocalTempPath(dir, 'download-staging');
    const stagingHandle = cleanup.addLocal(staging);
    await fs.mkdir(staging, { mode: 0o700 });
    const extractBinary = await resolveLocalExtractTar();
    // Windows 的 GNU tar（MSYS）需要正斜杠路径与 --force-local，否则 "C:\..."
    // 会被当作 host:path 或无法打开。
    const tarPath = (p: string): string =>
      extractBinary !== undefined ? p.replace(/\\/g, '/') : p;
    // -p 保留归档中的权限位，使本地 manifest 与远端源清单可按 mode 严格比较。
    const extractArgv = ['-C', tarPath(path.resolve(staging))];
    if (extractBinary !== undefined) extractArgv.push('--force-local');
    extractArgv.push('-xpf', tarPath(path.resolve(archive)));
    const extractRun = await runLocalTar({
      argv: extractArgv,
      ...(extractBinary !== undefined ? { binary: extractBinary } : {}),
      timeoutMs: input.timeoutMs ?? 300_000,
      label: 'local tar extract',
    });
    lastRun = extractRun;
    const extractFailure = tarFailure(extractRun);
    if (extractFailure !== undefined) return emptyFailure(base, extractFailure, extractRun);

    const localManifest = await buildLocalManifest({
      root: staging,
      limits: deps.limits,
      hash: true,
    });
    const diff = diffPortable(sourceManifest, localManifest);
    const mismatch = manifestMismatch(diff, 'local');
    if (mismatch !== undefined) return emptyFailure(base, mismatch, extractRun);

    if (localState.exists) {
      const backup = newLocalTempPath(dir, 'backup');
      await fs.rename(localTarget.path, backup);
      try {
        await fs.rename(staging, localTarget.path);
      } catch (err) {
        let rolledBack = false;
        try {
          await fs.rename(backup, localTarget.path);
          rolledBack = true;
        } catch {
          rolledBack = false;
        }
        if (!rolledBack) {
          // 回滚失败：保留备份原样（不清理），并在失败事实中标注。
          const failure = internalFailure(
            'local_replace_failed',
            'local directory replace failed and rollback did not complete',
          );
          failure.details = { ...(failure.details ?? {}), backupPath: backup };
          return {
            ...emptyFailure(base, failure, lastRun),
            backupPath: backup,
          };
        }
        throw err;
      }
      try {
        await fs.rm(backup, { recursive: true, force: true });
      } catch {
        // 备份残留不影响已完成的替换。
      }
    } else {
      await fs.rename(staging, localTarget.path);
    }
    cleanup.release(stagingHandle);

    const { files, bytes } = countFiles(sourceManifest);
    return {
      ok: true,
      direction: 'download',
      kind: 'directory',
      sourcePath: absolute,
      targetPath: localTarget.path,
      files,
      bytes,
      manifestDigest: digestManifest(sourceManifest),
      verified: true,
      atomicReplace: true,
      overwritten: localState.exists,
      durationMs: Date.now() - startedAt,
      ...(lastRun !== undefined ? { run: runFacts(lastRun) } : {}),
    };
  } catch (err) {
    return emptyFailure(base, transferErrorToToolError(err), lastRun);
  } finally {
    const report = await cleanup.run();
    if (report.failures.length > 0) {
      deps.ctx.log.warn(
        { failures: report.failures, tool: 'downloadTree' },
        'transfer cleanup incomplete',
      );
    }
  }
}
