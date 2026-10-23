import type { CallToolResult } from '@modelcontextprotocol/server';
import type { HostLimiter } from '../ssh/host-limiter.js';
import { errorToToolError, toolErrorResult, type ToolContext } from '../tools/common.js';
import type { ToolError } from '../types.js';
import { withHostLease, type HostLease } from './lease.js';
import { resolveTarget, type ResolvedTarget } from './target.js';
import { checkTrust, trustFactToToolError } from './trust.js';

/** audit / format 阶段可见的全部事实。 */
export interface OperationArgs<Plan, Produced> {
  target: ResolvedTarget;
  plan: Plan;
  produced: Produced;
  lease: HostLease;
  failure?: ToolError;
}

/**
 * 复用的 ssh 操作管线钩子。执行顺序：
 * resolveTarget -> checkTrust -> prepare（租约外）-> 获取主机租约 ->
 * execute -> classifyFailure -> audit -> format。
 */
export interface SshOperationHooks<Plan, Produced> {
  input: { host?: string };
  ctx: ToolContext;
  /** 测试可注入；默认进程单例。 */
  limiter?: HostLimiter;
  /** 租约外准备（构建命令计划、解析超时等）；抛错即 Policy/Internal 结果。 */
  prepare: (target: ResolvedTarget) => Plan | Promise<Plan>;
  /** 持有租约执行；返回原始运行事实。 */
  execute: (args: { target: ResolvedTarget; plan: Plan; lease: HostLease }) => Promise<Produced>;
  /** 运行事实 -> ToolError；undefined 表示成功。 */
  classifyFailure?: (produced: Produced) => ToolError | undefined;
  /** 审计（不抛）：appendAudit 永不 reject，其他异常由外层 catch 兜底。 */
  audit?: (args: OperationArgs<Plan, Produced>) => Promise<void> | void;
  format: (args: OperationArgs<Plan, Produced>) => CallToolResult;
}

/**
 * 运行一次 ssh 操作并返回 MCP 结果。信任门禁在任何 spawn 之前；
 * 任何异常（包括钩子内）都转为 isError 结果，绝不向传输层抛出。
 */
export async function runSshOperation<Plan, Produced>(
  hooks: SshOperationHooks<Plan, Produced>,
): Promise<CallToolResult> {
  let alias: string | undefined;
  try {
    const target = await resolveTarget(hooks.input, hooks.ctx);
    alias = target.host.alias;

    const trust = await checkTrust({
      alias: target.host.alias,
      host: target.host,
      paths: hooks.ctx.paths,
      log: hooks.ctx.log,
    });
    if (!trust.ok) {
      return toolErrorResult(trustFactToToolError(trust.fact, hooks.ctx.log), alias);
    }

    // 准备阶段在租约外：慢速校验不应占住主机并发槽位。
    const plan = await hooks.prepare(target);

    return await withHostLease(
      target.destination,
      async (lease) => {
        const produced = await hooks.execute({ target, plan, lease });
        const failure = hooks.classifyFailure?.(produced);
        const args: OperationArgs<Plan, Produced> = {
          target,
          plan,
          produced,
          lease,
          ...(failure !== undefined ? { failure } : {}),
        };
        if (hooks.audit !== undefined) await hooks.audit(args);
        return hooks.format(args);
      },
      hooks.limiter,
    );
  } catch (e) {
    return toolErrorResult(errorToToolError(e, hooks.ctx.log), alias);
  }
}
