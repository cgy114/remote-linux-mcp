/**
 * 指纹计算与 key blob 校验统一由 util/fingerprint.ts 实现；这里重导出以保持
 * trust 模块的既有导入路径不变。
 */
export { fingerprintKey, isValidKeyBlob } from '../util/fingerprint.js';

/** 单行展示：`SHA256:xxxx  host:port (ED25519)`。 */
export function formatFingerprintDisplay(input: {
  host: string;
  port: number;
  algorithm: string;
  fingerprint: string;
}): string {
  return `${input.fingerprint}  ${input.host}:${input.port} (${input.algorithm.toUpperCase()})`;
}
