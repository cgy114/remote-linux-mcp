import { appendAudit, auditFilePath } from '../audit/audit.js';
import {
  buildTransferAuditRecord,
  type TransferDirection,
} from '../audit/transfer-audit.js';
import type { ResolvedTarget } from '../pipeline/target.js';
import { fileLimitsFrom } from '../transfer/file-policy.js';
import type { TransferDeps } from '../transfer/deps.js';
import type { TransferFacts } from '../transfer/single-file.js';

import type { ToolError } from '../types.js';
import type { ToolAnnotations, ToolContext } from './common.js';

/** 修改型传输工具的统一注解。 */
export const TRANSFER_ANNOTATIONS: ToolAnnotations = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: true,
};

/** ssh_read_file 的只读注解。 */
export const READ_FILE_ANNOTATIONS: ToolAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
};

/** 以目标主机的 files 配置构造本次传输的依赖（deadline 从调用时刻起算）。 */
export function makeTransferDeps(target: ResolvedTarget, ctx: ToolContext): TransferDeps {
  return {
    target,
    knownHostsFile: ctx.paths.knownHostsFile,
    log: ctx.log,
    limits: fileLimitsFrom(target.config.files),
    deadlineMs: Date.now() + target.config.files.transferTimeoutMs,
  };
}

/** 传输事实 -> ToolError；undefined 表示成功。 */
export function classifyTransferFacts(facts: TransferFacts): ToolError | undefined {
  return facts.failure;
}

/** 审计只需要的事实摘要；TransferFacts / ReadFacts / WriteFacts 都可满足。 */
export interface TransferAuditSummary {
  ok: boolean;
  failure?: ToolError;
  files: number;
  bytes: number;
  verified: boolean;
  run?: import('../audit/transfer-audit.js').TransferRunFacts;
}

export interface TransferAuditArgs {
  tool: string;
  ctx: ToolContext;
  input: { host?: string };
  direction: TransferDirection;
  target?: ResolvedTarget;
  sourcePath?: string;
  targetPath?: string;
  files?: number;
  bytes?: number;
  facts?: TransferAuditSummary;
  failure?: ToolError;
  /** spawn 之前被拒绝（trust/prepare）；outcome 强制为 denied，queue_ms=0。 */
  denied?: boolean;
  /** 等待主机租约的毫秒数；denied（spawn 之前）固定为 0。 */
  queueMs?: number;
}

/**
 * 追加一条传输审计记录。记录只含路径摘要与退出事实，绝不含文件内容、
 * stdout/stderr 或凭据。任何异常都被吞掉，调用方不会被 reject。
 */
export async function appendTransferAudit(args: TransferAuditArgs): Promise<void> {
  try {
    const facts = args.facts;
    const failure = args.failure ?? facts?.failure;
    const record = buildTransferAuditRecord({
      tool: args.tool,
      ...(args.target !== undefined
        ? { alias: args.target.host.alias, destination: args.target.destination }
        : args.input.host !== undefined
          ? { alias: args.input.host }
          : {}),
      direction: args.direction,
      ...(args.sourcePath !== undefined ? { sourcePath: args.sourcePath } : {}),
      ...(args.targetPath !== undefined ? { targetPath: args.targetPath } : {}),
      files: facts?.files ?? args.files ?? 0,
      bytes: facts?.bytes ?? args.bytes ?? 0,
      ...(facts?.run !== undefined ? { run: facts.run } : {}),
      ...(failure !== undefined ? { failure: { code: failure.code, kind: failure.kind } } : {}),
      ...(facts?.verified !== undefined ? { verified: facts.verified } : {}),
    });
    if (args.denied === true) record.outcome = 'denied';
    await appendAudit(
      { ...record, queue_ms: args.denied === true ? 0 : args.queueMs ?? 0 },
      { file: auditFilePath(args.ctx.paths.configDir), log: args.ctx.log },
    );
  } catch (err) {
    try {
      args.ctx.log.warn(
        { err: err instanceof Error ? err.message : String(err), tool: args.tool },
        'transfer audit failed',
      );
    } catch {
      // 日志失败不影响调用方。
    }
  }
}
