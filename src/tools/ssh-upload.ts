import type { CallToolResult } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { UsageError } from '../errors/classes.js';
import { runSshOperation } from '../pipeline/operation.js';
import type { ResolvedTarget } from '../pipeline/target.js';
import {
  assertRemotePathAllowed,
  buildRemoteDenyLists,
  normalizeRemotePath,
} from '../policy/remote-path.js';
import type { TransferDeps } from '../transfer/deps.js';
import { assertTransferEnabled, fileLimitsFrom } from '../transfer/file-policy.js';
import {
  buildLocalManifest,
  resolveLocalSource,
  type LocalSource,
} from '../transfer/local-path.js';
import type { ManifestEntry } from '../transfer/manifest.js';
import { uploadSingleFile } from '../transfer/single-file.js';
import { uploadTree } from '../transfer/directory.js';
import type { ToolContext } from './common.js';
import {
  appendTransferAudit,
  classifyTransferFacts,
  makeTransferDeps,
} from './transfer-common.js';
import { formatTransferResult } from './transfer-format.js';

export const sshUploadInput = z
  .object({
    host: z.string().min(1).max(64).optional(),
    local_path: z.string().min(1).max(4096),
    remote_path: z.string().min(1).max(4096),
    recursive: z.boolean().optional(),
    overwrite: z.boolean().optional(),
  })
  .strict();

export type SshUploadInput = z.infer<typeof sshUploadInput>;

/** prepare 阶段的产物；只在租约外做本地检查与路径规范化，不 spawn。 */
export interface UploadPlan {
  kind: 'file' | 'directory';
  local: LocalSource;
  manifest: ManifestEntry[];
  remote: string;
  remoteRaw: string;
  overwrite: boolean;
  denyWrite: string[];
  timeoutMs: number;
}

function remapLocalDenied(err: unknown): Error {
  if (err instanceof UsageError && err.code === 'local_path_denied') {
    return new UsageError(err.message, { code: 'local_root_not_allowed' });
  }
  return err instanceof Error ? err : new Error(String(err));
}

/**
 * 构建上传计划（纯本地）：files 开关 -> 本地源解析（local_roots）-> 远端路径
 * 规范化与写 deny -> 目录清单。任何违规抛 UsageError，由管线转为 Policy。
 */
export async function buildUploadPlan(
  input: SshUploadInput,
  target: ResolvedTarget,
): Promise<UploadPlan> {
  const files = target.config.files;
  assertTransferEnabled(files);

  const limits = fileLimitsFrom(files);
  let local: LocalSource;
  try {
    local = await resolveLocalSource({
      path: input.local_path,
      roots: files.localRoots,
      limits,
      allowDir: input.recursive === true,
    });
  } catch (err) {
    throw remapLocalDenied(err);
  }

  const normalized = normalizeRemotePath(input.remote_path, target.host.cwd);
  const denyWrite = buildRemoteDenyLists(files).write;
  assertRemotePathAllowed(normalized.absolute, 'write', denyWrite);

  const manifest =
    local.kind === 'dir'
      ? await buildLocalManifest({ root: local.realPath, limits, hash: true })
      : [];

  return {
    kind: local.kind === 'dir' ? 'directory' : 'file',
    local,
    manifest,
    remote: normalized.absolute,
    remoteRaw: input.remote_path,
    overwrite: input.overwrite === true,
    denyWrite,
    timeoutMs: files.transferTimeoutMs,
  };
}

function executeUpload(deps: TransferDeps, plan: UploadPlan) {
  if (plan.kind === 'file') {
    return uploadSingleFile({
      deps,
      local: plan.local,
      remote: plan.remote,
      overwrite: plan.overwrite,
      denyWrite: plan.denyWrite,
      timeoutMs: plan.timeoutMs,
    });
  }
  return uploadTree({
    deps,
    local: plan.local,
    manifest: plan.manifest,
    remote: plan.remote,
    overwrite: plan.overwrite,
    denyWrite: plan.denyWrite,
    timeoutMs: plan.timeoutMs,
  });
}

/**
 * ssh_upload：复用管线（resolve -> trust -> prepare -> lease -> execute -> audit -> format）。
 * 单文件走 sftp + sha256；recursive 目录走 tar over ssh + manifest 校验。
 * 任何失败都以 isError 结果返回，不向传输层抛出。
 */
export async function sshUpload(
  input: SshUploadInput,
  ctx: ToolContext,
): Promise<CallToolResult> {
  return runSshOperation<UploadPlan, Awaited<ReturnType<typeof executeUpload>>>({
    input,
    ctx,
    toolName: 'ssh_upload',
    prepare: (target) => buildUploadPlan(input, target),
    execute: ({ target, plan }) => executeUpload(makeTransferDeps(target, ctx), plan),
    classifyFailure: (facts) => classifyTransferFacts(facts),
    auditDenied: async ({ ctx: auditCtx, error, target }) => {
      await appendTransferAudit({
        tool: 'ssh_upload',
        ctx: auditCtx,
        input,
        direction: 'upload',
        ...(target !== undefined ? { target } : {}),
        sourcePath: input.local_path,
        targetPath: input.remote_path,
        failure: error,
        denied: true,
      });
    },
    audit: async ({ target, plan, produced, lease }) => {
      await appendTransferAudit({
        tool: 'ssh_upload',
        ctx,
        input,
        direction: 'upload',
        target,
        sourcePath: plan.local.path,
        targetPath: produced.targetPath,
        facts: produced,
        queueMs: lease.queueMs,
      });
    },
    format: ({ target, produced, lease }) =>
      formatTransferResult({
        tool: 'ssh_upload',
        host: target.host.alias,
        facts: produced,
        queueMs: lease.queueMs,
      }),
  });
}
