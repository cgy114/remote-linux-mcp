import { randomBytes } from 'node:crypto';
import { UsageError } from '../errors/classes.js';
import { dirnameRemote, normalizeRemotePath, renderRemoteShellPath } from '../policy/remote-path.js';
import type { RunResult, ToolError } from '../types.js';
import { runRemoteCommand, type TransferDeps } from './deps.js';
import { classifyTransportRun } from './errors.js';

export interface RemoteCommandOutcome {
  ok: boolean;
  run: RunResult;
  error?: ToolError;
}

function outcome(run: RunResult, label: string): RemoteCommandOutcome {
  const error = classifyTransportRun(run, { label });
  return error === undefined ? { ok: true, run } : { ok: false, run, error };
}

function rooted(p: string): string {
  return normalizeRemotePath(p, '/').absolute;
}

/** 与目标同目录的临时路径：`.remote-mcp-tmp-<16 hex>`。 */
export function newRemoteTempPath(target: string): string {
  const dir = dirnameRemote(target);
  const name = `.remote-mcp-tmp-${randomBytes(8).toString('hex')}`;
  return dir === '/' ? `/${name}` : `${dir}/${name}`;
}

function guardRoot(p: string, action: string): string {
  const normalized = rooted(p);
  if (normalized === '/' || normalized === '~') {
    throw new UsageError(`refusing to ${action} the filesystem root or home directory`, {
      code: 'remote_path_invalid',
    });
  }
  return normalized;
}

/** 创建远端目录（mkdir -p）。 */
export async function createRemoteDirectory(
  deps: TransferDeps,
  remotePath: string,
): Promise<RemoteCommandOutcome> {
  const pathValue = rooted(remotePath);
  const run = await runRemoteCommand(
    deps,
    `mkdir -p -- ${renderRemoteShellPath(pathValue)}`,
    { label: `mkdir:${deps.target.host.alias}` },
  );
  return outcome(run, 'mkdir');
}

/** 递归删除远端目录/文件（rm -rf）；拒绝根目录与 home。 */
export async function removeRemoteTree(
  deps: TransferDeps,
  remotePath: string,
): Promise<RemoteCommandOutcome> {
  const pathValue = guardRoot(remotePath, 'remove');
  const run = await runRemoteCommand(
    deps,
    `rm -rf -- ${renderRemoteShellPath(pathValue)}`,
    { label: `rm:${deps.target.host.alias}` },
  );
  return outcome(run, 'rm');
}

export interface SwapRemoteInput {
  staged: string;
  target: string;
  /** 备份路径；省略时使用同目录临时路径。 */
  backup?: string;
}

export interface SwapRemoteResult {
  ok: boolean;
  backup: string;
  run: RunResult;
  error?: ToolError;
  rolledBack: boolean;
}

/**
 * 原子替换：target -> backup，staged -> target；第二步失败时把 backup 移回。
 * 返回备份路径（不存在的目标不会产生备份，但路径仍返回，供 cleanup 幂等处理）。
 */
export async function swapRemoteIntoPlace(
  deps: TransferDeps,
  input: SwapRemoteInput,
): Promise<SwapRemoteResult> {
  const target = guardRoot(input.target, 'replace');
  const staged = guardRoot(input.staged, 'replace');
  const backup = input.backup !== undefined ? rooted(input.backup) : newRemoteTempPath(target);
  if (target === staged) {
    throw new UsageError('staged path must differ from the target path', {
      code: 'remote_path_invalid',
    });
  }
  if (backup === target || backup === staged) {
    throw new UsageError('backup path must differ from staged and target paths', {
      code: 'remote_path_invalid',
    });
  }

  const t = renderRemoteShellPath(target);
  const s = renderRemoteShellPath(staged);
  const b = renderRemoteShellPath(backup);

  const backedUp = await runRemoteCommand(
    deps,
    `if test -e ${t} || test -L ${t}; then mv -f -- ${t} ${b} || exit 1; fi`,
    { label: `swap-backup:${deps.target.host.alias}` },
  );
  const backupOutcome = outcome(backedUp, 'swap backup');
  if (!backupOutcome.ok) {
    return {
      ok: false,
      backup,
      run: backedUp,
      ...(backupOutcome.error !== undefined ? { error: backupOutcome.error } : {}),
      rolledBack: false,
    };
  }

  const moved = await runRemoteCommand(deps, `mv -f -- ${s} ${t}`, {
    label: `swap-commit:${deps.target.host.alias}`,
  });
  const moveOutcome = outcome(moved, 'swap commit');
  if (moveOutcome.ok) {
    return { ok: true, backup, run: moved, rolledBack: false };
  }

  const rollback = await runRemoteCommand(
    deps,
    `if test -e ${b} || test -L ${b}; then mv -f -- ${b} ${t} || exit 1; fi`,
    { label: `swap-rollback:${deps.target.host.alias}` },
  );
  return {
    ok: false,
    backup,
    run: moved,
    ...(moveOutcome.error !== undefined ? { error: moveOutcome.error } : {}),
    rolledBack: rollback.exitCode === 0,
  };
}
