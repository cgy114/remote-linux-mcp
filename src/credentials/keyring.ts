import {
  assertCredentialName,
  assertCredentialSecret,
  CredentialError,
  SecretMaterial,
  type WritableCredentialProvider,
} from './provider.js';

/** @napi-rs/keyring 的最小结构；便于测试注入替身。 */
export interface KeyringEntry {
  getPassword(): string | null;
  setPassword(password: string): void;
  deletePassword(): boolean;
}

export interface KeyringModule {
  Entry: new (service: string, username: string) => KeyringEntry;
}

export interface KeyringProviderOptions {
  /** keyring service 名；默认 remote-mcp。 */
  service?: string;
  /** 测试注入；默认动态 import('@napi-rs/keyring')。 */
  loadModule?: () => Promise<KeyringModule>;
}

const DEFAULT_SERVICE = 'remote-mcp';

function unavailable(cause?: unknown): CredentialError {
  return new CredentialError(
    'credential_unavailable',
    'credential store is unavailable (keyring backend cannot be loaded or accessed)',
    cause !== undefined ? { cause } : undefined,
  );
}

/**
 * 基于操作系统凭据库（Windows Credential Manager / macOS Keychain /
 * Linux Secret Service）的 provider。
 *
 * `@napi-rs/keyring` 通过动态 import 加载，因此原生绑定缺失时模块本身仍可加载，
 * 只有实际调用才会得到 credential_unavailable。
 */
export function createKeyringCredentialProvider(
  options: KeyringProviderOptions = {},
): WritableCredentialProvider {
  const service = options.service ?? DEFAULT_SERVICE;
  const loadModule =
    options.loadModule ?? ((): Promise<KeyringModule> => import('@napi-rs/keyring') as Promise<KeyringModule>);

  let modulePromise: Promise<KeyringModule> | undefined;
  const module = (): Promise<KeyringModule> => {
    modulePromise ??= loadModule().catch((err: unknown) => {
      throw unavailable(err);
    });
    return modulePromise;
  };

  const entry = async (name: string): Promise<KeyringEntry> => {
    assertCredentialName(name);
    try {
      const mod = await module();
      return new mod.Entry(service, name);
    } catch (err) {
      if (err instanceof CredentialError) throw err;
      throw unavailable(err);
    }
  };

  return {
    id: 'keyring',

    async get(name: string): Promise<SecretMaterial> {
      const handle = await entry(name);
      let raw: string | null;
      try {
        raw = handle.getPassword();
      } catch (err) {
        throw unavailable(err);
      }
      if (raw === null) {
        throw new CredentialError('credential_not_found', `credential ${name} not found`);
      }
      let bytes: Buffer | undefined;
      try {
        bytes = assertCredentialSecret(raw);
      } catch (err) {
        if (err instanceof CredentialError) throw err;
        throw new CredentialError('credential_invalid', 'stored credential is not usable');
      }
      try {
        return new SecretMaterial(bytes);
      } finally {
        bytes.fill(0);
      }
    },

    async exists(name: string): Promise<boolean> {
      const handle = await entry(name);
      try {
        // keyring API 没有仅查元数据的方法；这里只判断是否为 null，
        // 不把明文交给任何调用方。
        return handle.getPassword() !== null;
      } catch (err) {
        throw unavailable(err);
      }
    },

    async set(name: string, secret: string | Buffer): Promise<void> {
      const handle = await entry(name);
      const bytes = assertCredentialSecret(secret);
      try {
        handle.setPassword(bytes.toString('utf8'));
      } catch (err) {
        throw unavailable(err);
      } finally {
        bytes.fill(0);
      }
    },

    async delete(name: string): Promise<boolean> {
      const handle = await entry(name);
      try {
        return handle.deletePassword();
      } catch (err) {
        throw unavailable(err);
      }
    },
  };
}
