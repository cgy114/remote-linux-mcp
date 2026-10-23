import type { CallToolResult } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { runSshOperation } from '../pipeline/operation.js';
import type { ResolvedTarget } from '../pipeline/target.js';
import {
  assertRemotePathAllowed,
  buildRemoteDenyLists,
  normalizeRemotePath,
} from '../policy/remote-path.js';
import { readRemoteFile, type ReadFacts } from '../transfer/remote-file.js';
import type { ToolContext } from './common.js';
import {
  appendTransferAudit,
  makeTransferDeps,
} from './transfer-common.js';
import { formatReadFileResult } from './transfer-format.js';

const DEFAULT_READ_BYTES = 1024 * 1024;
const MAX_READ_BYTES = 8 * 1024 * 1024;

export const sshReadFileInput = z
  .object({
    host: z.string().min(1).max(64).optional(),
    path: z.string().min(1).max(4096),
    tail_lines: z.number().int().min(1).max(1_000_000).optional(),
    max_bytes: z.number().int().min(1).max(MAX_READ_BYTES).optional(),
  })
  .strict();

export type SshReadFileInput = z.infer<typeof sshReadFileInput>;

export interface ReadPlan {
  remote: string;
  remoteRaw: string;
  maxBytes: number;
  tailLines?: number;
  denyRead: string[];
  timeoutMs: number;
}

/** prepare：远端路径规范化 + 读 deny；maxBytes 收敛到 files.max_file_bytes。 */
export function buildReadPlan(input: SshReadFileInput, target: ResolvedTarget): ReadPlan {
  const files = target.config.files;
  const normalized = normalizeRemotePath(input.path, target.host.cwd);
  const denyRead = buildRemoteDenyLists(files).read;
  assertRemotePathAllowed(normalized.absolute, 'read', denyRead);

  return {
    remote: normalized.absolute,
    remoteRaw: input.path,
    maxBytes: Math.min(input.max_bytes ?? DEFAULT_READ_BYTES, files.maxFileBytes),
    ...(input.tail_lines !== undefined ? { tailLines: input.tail_lines } : {}),
    denyRead,
    timeoutMs: files.transferTimeoutMs,
  };
}

/**
 * ssh_read_file：只读。读取远端文件内容（UTF-8 文本或 base64），并返回整文件
 * sha256/size。读 deny（如 ~/.ssh）在任何 spawn 之前生效。
 */
export async function sshReadFile(
  input: SshReadFileInput,
  ctx: ToolContext,
): Promise<CallToolResult> {
  return runSshOperation<ReadPlan, ReadFacts>({
    input,
    ctx,
    prepare: (target) => buildReadPlan(input, target),
    execute: ({ target, plan }) =>
      readRemoteFile({
        deps: makeTransferDeps(target, ctx),
        remote: plan.remote,
        maxBytes: plan.maxBytes,
        ...(plan.tailLines !== undefined ? { tailLines: plan.tailLines } : {}),
        denyRead: plan.denyRead,
        timeoutMs: plan.timeoutMs,
      }),
    classifyFailure: (facts) => facts.failure,
    auditDenied: async ({ ctx: auditCtx, error, target }) => {
      await appendTransferAudit({
        tool: 'ssh_read_file',
        ctx: auditCtx,
        input,
        direction: 'download',
        ...(target !== undefined ? { target } : {}),
        sourcePath: input.path,
        failure: error,
        denied: true,
      });
    },
    audit: async ({ target, plan, produced, lease }) => {
      await appendTransferAudit({
        tool: 'ssh_read_file',
        ctx,
        input,
        direction: 'download',
        target,
        sourcePath: plan.remoteRaw,
        targetPath: produced.path,
        facts: {
          ok: produced.ok,
          ...(produced.failure !== undefined ? { failure: produced.failure } : {}),
          files: produced.ok ? 1 : 0,
          bytes: produced.returnedBytes,
          verified: produced.ok,
          ...(produced.run !== undefined ? { run: produced.run } : {}),
        },
        queueMs: lease.queueMs,
      });
    },
    format: ({ target, produced, lease }) =>
      formatReadFileResult({
        host: target.host.alias,
        facts: produced,
        queueMs: lease.queueMs,
      }),
  });
}
