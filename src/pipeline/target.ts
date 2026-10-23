import { UsageError } from '../errors/classes.js';
import { assertAlias } from '../policy/alias.js';
import { assertTarget, effectiveHost, selectJumpSpec } from '../policy/target.js';
import type { ToolContext } from '../tools/common.js';
import type { EffectiveHost, RemoteConfig } from '../types.js';

/** 已解析并校验过的目标主机。 */
export interface ResolvedTarget {
  config: RemoteConfig;
  host: EffectiveHost;
  destination: string;
}

/**
 * 解析目标主机：host > defaults.default_host。缺失时抛 missing_host，
 * 其余用 policy 层校验（alias、jump 链、目标三元组）。
 */
export async function resolveTarget(
  input: { host?: string },
  ctx: ToolContext,
): Promise<ResolvedTarget> {
  const config = await ctx.getConfig();
  const alias = input.host ?? config.defaults.defaultHost;
  if (alias === undefined || alias === '') {
    throw new UsageError('missing_host', { code: 'missing_host' });
  }
  const checked = assertAlias(alias);
  const host = effectiveHost(config, checked);
  const jumps = selectJumpSpec(host.proxyJump);
  assertTarget({ user: host.user, host: host.host, port: host.port, jumps });
  return { config, host, destination: `${host.user}@${host.host}:${host.port}` };
}

/** 兼容旧名（ssh_exec 的历史导出）：resolveTarget 的薄包装。 */
export async function resolveExecTarget(
  input: { host?: string },
  ctx: ToolContext,
): Promise<ResolvedTarget> {
  return resolveTarget(input, ctx);
}
