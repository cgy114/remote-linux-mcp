import type { CallToolResult } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { classifyExit, stderrSignatures, toUserError } from '../errors/classify.js';
import { assertAlias } from '../policy/alias.js';
import { assertTarget, effectiveHost, selectJumpSpec } from '../policy/target.js';
import { preflightAuth, preflightJump } from '../ssh/preflight.js';
import { parseCheckOutput, runHostCheckProbe } from '../ssh/probe.js';
import { evaluateTrust } from '../trust/gate.js';
import type { ErrorFacts } from '../types.js';
import { singleFlight } from '../util/inflight.js';
import { errorToToolError, toolErrorResult, type ToolContext } from './common.js';
import { formatCheckResult } from './format.js';

export const hostCheckInput = z.object({ alias: z.string().min(1).max(64) }).strict();
export type HostCheckInput = z.infer<typeof hostCheckInput>;

/**
 * host_check：按固定顺序执行检查，任何失败都以结果返回（不抛）。
 * 信任门禁在任何 spawn 之前执行。同别名的在途请求被合并（不缓存结果）。
 */
export async function hostCheck(input: HostCheckInput, ctx: ToolContext): Promise<CallToolResult> {
  let validAlias: string | undefined;
  try {
    const alias = assertAlias(input.alias);
    validAlias = alias;
    return await singleFlight(`host_check:${alias}`, () => runCheck(alias, ctx));
  } catch (e) {
    return toolErrorResult(errorToToolError(e, ctx.log), validAlias);
  }
}

async function runCheck(alias: string, ctx: ToolContext): Promise<CallToolResult> {
  // 2. 配置 -> 有效主机 -> 跳板 -> 目标校验（抛出的 UsageError/ConfigError 由外层转为 Policy）
  const config = await ctx.getConfig();
  const host = effectiveHost(config, alias);
  const jumps = selectJumpSpec(host.proxyJump);
  assertTarget({ user: host.user, host: host.host, port: host.port, jumps });

  // 3. 信任门禁：登记簿 + 专用 known_hosts。读取失败按 fail-closed 处理。
  const trust = await evaluateTrust({ alias: host.alias, host, paths: ctx.paths, log: ctx.log });
  if (!trust.ok) {
    const fact = trust.fact;
    return toolErrorResult(
      toUserError({ phase: 'trust', ...(fact.reason !== undefined ? { reason: fact.reason } : {}), ...(fact.stderr !== undefined ? { stderr: fact.stderr } : {}) }, ctx.log),
      alias,
    );
  }

  // 4. 认证前置检查
  const auth = await preflightAuth({ host, log: ctx.log });
  if (!auth.ok) {
    return toolErrorResult(toUserError(auth.fact, ctx.log), alias);
  }

  // 5. 跳板前置检查（仅在有跳板时）
  if (jumps.length > 0) {
    const jump = await preflightJump({ jumps, log: ctx.log });
    if (!jump.ok) {
      return toolErrorResult(toUserError(jump.fact, ctx.log), alias);
    }
  }

  // 6. 运行探测（超时与输出上限来自有效主机配置）
  const run = await runHostCheckProbe({
    host,
    paths: ctx.paths,
    timeoutMs: host.timeouts.checkMs,
    maxOutputBytes: host.maxOutputBytes,
    log: ctx.log,
  });

  // 7. 失败：退出事实 + stderr 特征 -> 用户错误
  if (run.spawnError !== undefined || run.timedOut || run.exitCode !== 0) {
    const facts: ErrorFacts = {
      phase: 'probe',
      ...classifyExit(run),
      stderr: run.stderr,
      signatures: stderrSignatures(run.stderr),
    };
    return toolErrorResult(toUserError(facts, ctx.log), alias);
  }

  // 8. 成功：解析并格式化
  const facts = parseCheckOutput(run.stdout);
  return formatCheckResult({ alias, ok: true, facts, latencyMs: run.durationMs });
}
