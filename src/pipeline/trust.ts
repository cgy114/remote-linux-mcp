import { toUserError } from '../errors/classify.js';
import type { TrustCheck } from '../policy/target.js';
import { evaluateTrust } from '../trust/gate.js';
import type { Alias, EffectiveHost, ErrorFacts, Logger, MCPPaths, ToolError } from '../types.js';

/**
 * 信任门禁：读取登记簿与专用 known_hosts，判断别名的主机密钥是否已固定。
 * 不抛异常；任何读取失败都 fail-closed。
 */
export async function checkTrust(input: {
  alias: Alias;
  host: EffectiveHost;
  paths: MCPPaths;
  log: Logger;
}): Promise<TrustCheck> {
  return evaluateTrust(input);
}

/**
 * 信任事实 -> ToolError。只取 reason/stderr，phase 固定为 trust；
 * 其余事实字段（如 exitCode）不会泄露到错误里。
 */
export function trustFactToToolError(fact: Partial<ErrorFacts>, log?: Logger): ToolError {
  return toUserError(
    {
      phase: 'trust',
      ...(fact.reason !== undefined ? { reason: fact.reason } : {}),
      ...(fact.stderr !== undefined ? { stderr: fact.stderr } : {}),
    },
    log,
  );
}
