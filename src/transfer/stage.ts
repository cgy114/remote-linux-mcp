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
  /** 原 target 内容仍在 target，或提交失败后已回滚到 target。 */
  rolledBack: boolean;
  /** 与 rolledBack 同义：原内容是否仍然/重新位于 target。 */
  restored: boolean;
}

/**
 * 原子替换：target -> backup，staged -> target；提交失败时回滚。
 * 全部步骤在**一次**远端命令中完成，退出码语义：
 *   0 成功；1 备份阶段失败（target 未被移动）；2 提交失败但已回滚（或无需回滚）；
 *   3 提交失败且回滚失败（原内容留在 backup）。
 * 路径全部经 renderRemoteShellPath（单引号引用），不做裸拼接。
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

  // 单次往返：备份 -> 提交 -> 成功清理备份 / 失败回滚。
  const script = [
    `if [ -e ${t} ] || [ -L ${t} ]; then`,
    `  mv -f -- ${t} ${b} || exit 1`,
    'fi',
    `if mv -f -- ${s} ${t}; then`,
    `  if [ -e ${b} ] || [ -L ${b} ]; then rm -rf -- ${b} || :; fi`,
    '  exit 0',
    'fi',
    `if [ -e ${b} ] || [ -L ${b} ]; then`,
    `  mv -f -- ${b} ${t} 2>/dev/null && exit 2`,
    '  exit 3',
    'fi',
    'exit 2',
  ].join('\n');

  const run = await runRemoteCommand(deps, script, {
    label: `swap:${deps.target.host.alias}`,
  });
  const failure = classifyTransportRun(run, { label: 'swap' });
  if (failure === undefined) {
    return { ok: true, backup, run, rolledBack: false, restored: true };
  }

  const exitCode = run.exitCode;
  const restored = exitCode === 1 || exitCode === 2;
  const stage =
    exitCode === 1 ? 'backup' : exitCode === 2 ? 'commit' : exitCode === 3 ? 'rollback' : undefined;
  const error =
    stage === undefined
      ? failure
      : { ...failure, details: { ...(failure.details ?? {}), stage } };
  return { ok: false, backup, run, error, rolledBack: restored, restored };
}
