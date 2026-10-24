import { createKeyringCredentialProvider } from './keyring.js';
import type { CredentialProvider, WritableCredentialProvider } from './provider.js';

export * from './provider.js';
export * from './keyring.js';

let provider: WritableCredentialProvider | undefined;

/** 进程单例；首次使用时才加载 keyring 原生绑定。 */
export function getCredentialProvider(): WritableCredentialProvider {
  provider ??= createKeyringCredentialProvider();
  return provider;
}

/**
 * 替换/清除单例（测试与嵌入方使用）。传 undefined 后下次 get 重新创建 keyring provider。
 * CLI 测试通过 runCredentialCommand 的 provider 参数注入，不依赖这里。
 */
export function setCredentialProvider(next?: CredentialProvider): void {
  provider = next as WritableCredentialProvider | undefined;
}
