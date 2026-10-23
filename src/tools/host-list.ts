import type { CallToolResult } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { ConfigError, UsageError } from '../errors/classes.js';
import { effectiveHost } from '../policy/target.js';
import { serializeError } from '../log.js';
import { fingerprintKey } from '../trust/fingerprint.js';
import { findHostKeyEntries, readKnownHosts } from '../trust/known-hosts.js';
import { loadTrustRegistry } from '../trust/registry.js';
import type {
  HostView,
  KnownHostEntry,
  RemoteConfig,
  Security,
  TrustRegistry,
} from '../types.js';
import { formatHostList } from './host-list-format.js';
import { policyError, toolErrorResult, type ToolContext } from './common.js';

export const hostListInput = z.object({}).strict();
export type HostListInput = z.infer<typeof hostListInput>;

export interface MergeHostViewInput {
  config: RemoteConfig;
  registry: TrustRegistry;
  knownHosts: KnownHostEntry[];
  security: Security;
}

/**
 * 纯函数：把配置、登记簿、known_hosts 合并为主机视图（按 alias 升序）。
 * trusted 需要：registry 中存在同别名 pin，且某条 known_hosts 条目的指纹与 pin 相等。
 * 不 spawn，不做任何 IO。
 */
export function mergeHostView(input: MergeHostViewInput): HostView[] {
  const { config, registry, knownHosts, security } = input;
  const pinnedPolicy = security.hostKeyPolicy === 'pinned';
  const aliases = Object.keys(config.hosts).sort();

  return aliases.map((alias): HostView => {
    const eff = effectiveHost(config, alias);
    const hostCfg = config.hosts[alias];

    const matches = findHostKeyEntries(knownHosts, eff.host, eff.port);
    const observed = matches.flatMap((e) => {
      try {
        return [fingerprintKey(e.keyBlob)];
      } catch {
        return [];
      }
    });

    const pin = Object.prototype.hasOwnProperty.call(registry.hosts, alias)
      ? registry.hosts[alias]
      : undefined;
    const trusted = pinnedPolicy && pin !== undefined && observed.includes(pin.fingerprint);

    const view: HostView = {
      alias,
      host: eff.host,
      user: eff.user,
      port: eff.port,
      trusted,
      knownHostsPresent: matches.length > 0,
      source: 'config',
    };
    if (pin !== undefined) view.pinnedFingerprint = pin.fingerprint;
    if (hostCfg?.description !== undefined) view.description = hostCfg.description;
    return view;
  });
}

/**
 * host_list：读取配置（失败 -> Policy 结果）、登记簿（失败 -> 降级为空表并标记 degraded）、
 * 专用 known_hosts（tolerant），合并后格式化输出。
 */
export async function hostList(_input: HostListInput, ctx: ToolContext): Promise<CallToolResult> {
  try {
    const config = await ctx.getConfig();

    let registry: TrustRegistry = { version: 1, hosts: {} };
    let degraded = false;
    try {
      registry = await loadTrustRegistry(ctx.paths.trustRegistryFile);
    } catch (err) {
      degraded = true;
      ctx.log.warn({ err: serializeError(err) }, 'trust registry unreadable; reporting all hosts as untrusted');
    }

    const { entries: knownHosts } = await readKnownHosts(ctx.paths.knownHostsFile);

    const hosts = mergeHostView({ config, registry, knownHosts, security: config.security });
    return formatHostList({
      hosts,
      configPath: config.sourcePath,
      source: ctx.paths.source,
      degraded,
    });
  } catch (e) {
    if (e instanceof ConfigError || e instanceof UsageError) {
      return toolErrorResult(policyError(e));
    }
    throw e;
  }
}
