import type { CallToolResult } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { runSshOperation } from '../pipeline/operation.js';
import type { ResolvedTarget } from '../pipeline/target.js';
import {
  assertRemotePathAllowed,
  buildRemoteDenyLists,
  normalizeRemotePath,
} from '../policy/remote-path.js';
import type { TransferDeps } from '../transfer/deps.js';
import { downloadSingleFile } from '../transfer/single-file.js';
import { downloadTree } from '../transfer/directory.js';
import { assertTransferEnabled, fileLimitsFrom } from '../transfer/file-policy.js';
import { resolveLocalTarget, type LocalTarget } from '../transfer/local-path.js';
import type { ToolContext } from './common.js';
import {
  appendTransferAudit,
  classifyTransferFacts,
  makeTransferDeps,
} from './transfer-common.js';
import { formatTransferResult } from './transfer-format.js';

export const sshDownloadInput = z
  .object({
    host: z.string().min(1).max(64).optional(),
    remote_path: z.string().min(1).max(4096),
    local_path: z.string().min(1).max(4096),
    recursive: z.boolean().optional(),
    overwrite: z.boolean().optional(),
  })
  .strict();

export type SshDownloadInput = z.infer<typeof sshDownloadInput>;

export interface DownloadPlan {
  recursive: boolean;
  remote: string;
  remoteRaw: string;
  localTarget: LocalTarget;
  overwrite: boolean;
  denyRead: string[];
  timeoutMs: number;
}

/**
 * 构建下载计划（纯本地）：files 开关 -> 远端路径规范化与读 deny ->
 * 本地目标门禁（父目录存在、白名单、非 symlink、overwrite）。
 */
export async function buildDownloadPlan(
  input: SshDownloadInput,
  target: ResolvedTarget,
): Promise<DownloadPlan> {
  const files = target.config.files;
  assertTransferEnabled(files);

  const normalized = normalizeRemotePath(input.remote_path, target.host.cwd);
  const denyRead = buildRemoteDenyLists(files).read;
  assertRemotePathAllowed(normalized.absolute, 'read', denyRead);

  const recursive = input.recursive === true;
  const localTarget = await resolveLocalTarget({
    path: input.local_path,
    roots: files.localRoots,
    limits: fileLimitsFrom(files),
    allowDir: recursive,
    overwrite: input.overwrite === true,
  });

  return {
    recursive,
    remote: normalized.absolute,
    remoteRaw: input.remote_path,
    localTarget,
    overwrite: input.overwrite === true,
    denyRead,
    timeoutMs: files.transferTimeoutMs,
  };
}

function executeDownload(deps: TransferDeps, plan: DownloadPlan) {
  if (plan.recursive) {
    return downloadTree({
      deps,
      remote: plan.remote,
      localTarget: plan.localTarget,
      overwrite: plan.overwrite,
      denyRead: plan.denyRead,
      timeoutMs: plan.timeoutMs,
    });
  }
  return downloadSingleFile({
    deps,
    remote: plan.remote,
    localTarget: plan.localTarget,
    overwrite: plan.overwrite,
    denyRead: plan.denyRead,
    timeoutMs: plan.timeoutMs,
  });
}

/**
 * ssh_download：单文件走 sftp + sha256 校验；recursive 目录走 tar over ssh +
 * manifest 校验。本地目标在 spawn 之前完成门禁。
 */
export async function sshDownload(
  input: SshDownloadInput,
  ctx: ToolContext,
): Promise<CallToolResult> {
  return runSshOperation<DownloadPlan, Awaited<ReturnType<typeof executeDownload>>>({
    input,
    ctx,
    toolName: 'ssh_download',
    prepare: (target) => buildDownloadPlan(input, target),
    execute: ({ target, plan }) => executeDownload(makeTransferDeps(target, ctx), plan),
    classifyFailure: (facts) => classifyTransferFacts(facts),
    auditDenied: async ({ ctx: auditCtx, error, target }) => {
      await appendTransferAudit({
        tool: 'ssh_download',
        ctx: auditCtx,
        input,
        direction: 'download',
        ...(target !== undefined ? { target } : {}),
        sourcePath: input.remote_path,
        targetPath: input.local_path,
        failure: error,
        denied: true,
      });
    },
    audit: async ({ target, plan, produced, lease }) => {
      await appendTransferAudit({
        tool: 'ssh_download',
        ctx,
        input,
        direction: 'download',
        target,
        sourcePath: plan.remoteRaw,
        targetPath: produced.targetPath,
        facts: produced,
        queueMs: lease.queueMs,
      });
    },
    format: ({ target, produced, lease }) =>
      formatTransferResult({
        tool: 'ssh_download',
        host: target.host.alias,
        facts: produced,
        queueMs: lease.queueMs,
      }),
  });
}
