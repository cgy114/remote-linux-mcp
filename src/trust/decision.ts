import type { Alias, PinnedHostKey, TrustDecision } from '../types.js';

/**
 * 纯函数：根据观察到的主机密钥与已固定的密钥决定动作。不抛。
 * - 无 pinned -> initial
 * - 指纹相同 -> unchanged（pinned 原样放入结果）
 * - 指纹不同 且 rotate -> rotate
 * - 指纹不同 且 !rotate -> reject（reason=fingerprint_mismatch）
 */
export function decideTrust(input: {
  alias: Alias;
  observed: PinnedHostKey;
  pinned?: PinnedHostKey;
  rotate: boolean;
}): TrustDecision {
  const { observed, pinned, rotate } = input;
  if (pinned === undefined) {
    return { action: 'initial', observed };
  }
  if (pinned.fingerprint === observed.fingerprint) {
    return { action: 'unchanged', observed, pinned };
  }
  if (rotate) {
    return { action: 'rotate', observed, pinned, reason: 'fingerprint_changed' };
  }
  return { action: 'reject', observed, pinned, reason: 'fingerprint_mismatch' };
}
