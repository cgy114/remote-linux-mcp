import type { TrustCheck } from '../policy/target.js';
import { checkTrustState } from '../policy/target.js';
import type { Alias, EffectiveHost, Logger, MCPPaths } from '../types.js';
import { readKnownHosts } from './known-hosts.js';
import { loadTrustRegistry } from './registry.js';

/**
 * 读取登记簿与 known_hosts 并判断信任状态。
 * 任何读取/校验异常都 fail-closed 为 not_registered（不抛）。
 */
export async function evaluateTrust(input: {
  alias: Alias;
  host: EffectiveHost;
  paths: MCPPaths;
  log: Logger;
}): Promise<TrustCheck> {
  const { alias, host, paths, log } = input;
  try {
    const registry = await loadTrustRegistry(paths.trustRegistryFile);
    const { entries } = await readKnownHosts(paths.knownHostsFile);
    return checkTrustState({ alias, host, registry, knownHosts: entries });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    log.warn({ alias, err: message }, 'trust state unreadable; failing closed');
    return {
      ok: false,
      fact: {
        reason: 'not_registered',
        stderr: `trust state could not be read: ${message}`,
      },
    };
  }
}
