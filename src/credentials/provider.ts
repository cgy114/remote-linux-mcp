/**
 * 凭据提供者抽象。
 *
 * 安全约定：
 * - 明文只存在于 SecretMaterial 的 Buffer 中，调用方用完后必须 wipe()（或使用 using）。
 * - 错误消息与日志绝不包含 secret；即使底层错误带有敏感内容，也只保留固定文案。
 * - 本模块不做持久化；keyring 实现在 keyring.ts。
 */

/** 凭据名：与配置中的 sudo.credential 使用同一字符集。 */
export const CREDENTIAL_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
/** 单个凭据的最大 UTF-8 字节数。 */
export const MAX_CREDENTIAL_BYTES = 1024;

export type CredentialErrorCode =
  | 'credential_not_found'
  | 'credential_invalid'
  | 'credential_timeout'
  | 'credential_unavailable';

/** 凭据层错误。message 是固定文案，不含 secret。 */
export class CredentialError extends Error {
  readonly code: CredentialErrorCode;

  constructor(code: CredentialErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'CredentialError';
    this.code = code;
  }
}

/** 校验凭据名；失败抛 credential_invalid。 */
export function assertCredentialName(name: unknown): string {
  if (typeof name !== 'string' || !CREDENTIAL_NAME_RE.test(name)) {
    throw new CredentialError(
      'credential_invalid',
      'credential name must match ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$',
    );
  }
  return name;
}

/**
 * 校验明文：非空、≤1024 字节、不含 NUL/CR/LF。
 * 失败抛 credential_invalid，消息不回显内容。
 */
export function assertCredentialSecret(secret: string | Buffer): Buffer {
  const bytes = typeof secret === 'string' ? Buffer.from(secret, 'utf8') : Buffer.from(secret);
  try {
    if (bytes.length === 0) {
      throw new CredentialError('credential_invalid', 'credential must not be empty');
    }
    if (bytes.length > MAX_CREDENTIAL_BYTES) {
      throw new CredentialError(
        'credential_invalid',
        `credential must be at most ${MAX_CREDENTIAL_BYTES} UTF-8 bytes`,
      );
    }
    if (bytes.includes(0x00)) {
      throw new CredentialError('credential_invalid', 'credential must not contain NUL');
    }
    if (bytes.includes(0x0a) || bytes.includes(0x0d)) {
      throw new CredentialError('credential_invalid', 'credential must not contain CR or LF');
    }
    return bytes;
  } catch (err) {
    bytes.fill(0);
    throw err;
  }
}

/**
 * 明文容器。内部 Buffer 归本对象所有；copy() 返回新的副本，
 * wipe()/fill() 只影响内部 Buffer。
 */
export class SecretMaterial {
  #buffer: Buffer;
  #disposed = false;

  constructor(value: string | Buffer) {
    this.#buffer = typeof value === 'string' ? Buffer.from(value, 'utf8') : Buffer.from(value);
  }

  get byteLength(): number {
    return this.#buffer.length;
  }

  get disposed(): boolean {
    return this.#disposed;
  }

  /** 返回内部 Buffer 的副本；调用方负责 wipe。 */
  copy(): Buffer {
    if (this.#disposed) throw new CredentialError('credential_invalid', 'credential has been wiped');
    return Buffer.from(this.#buffer);
  }

  /** 解码为字符串（仅用于必须接收 string 的底层 API）。 */
  toString(): string {
    if (this.#disposed) throw new CredentialError('credential_invalid', 'credential has been wiped');
    return this.#buffer.toString('utf8');
  }

  /** 用指定字节覆盖；默认 0。 */
  fill(byte = 0): this {
    this.#buffer.fill(byte & 0xff);
    return this;
  }

  /** 清零并标记为 disposed；幂等。 */
  wipe(): void {
    this.#buffer.fill(0);
    this.#disposed = true;
  }

  [Symbol.dispose](): void {
    this.wipe();
  }
}

export interface CredentialLookupOptions {
  timeoutMs?: number;
}

export interface CredentialProvider {
  readonly id: string;
  get(name: string, options?: CredentialLookupOptions): Promise<SecretMaterial>;
  /** 是否存在。实现可避免把明文返回给上层。 */
  exists?(name: string): Promise<boolean>;
}

export interface WritableCredentialProvider extends CredentialProvider {
  set(name: string, secret: string | Buffer): Promise<void>;
  delete(name: string): Promise<boolean>;
}

/** 测试与 CLI 注入用的内存 provider。 */
export class MemoryCredentialProvider implements WritableCredentialProvider {
  readonly id = 'memory';
  readonly #secrets = new Map<string, Buffer>();

  constructor(initial?: Record<string, string | Buffer>) {
    for (const [name, value] of Object.entries(initial ?? {})) {
      this.#secrets.set(assertCredentialName(name), Buffer.from(value));
    }
  }

  async get(name: string): Promise<SecretMaterial> {
    assertCredentialName(name);
    const value = this.#secrets.get(name);
    if (value === undefined) {
      throw new CredentialError('credential_not_found', `credential ${name} not found`);
    }
    return new SecretMaterial(value);
  }

  async exists(name: string): Promise<boolean> {
    assertCredentialName(name);
    return this.#secrets.has(name);
  }

  async set(name: string, secret: string | Buffer): Promise<void> {
    assertCredentialName(name);
    const bytes = assertCredentialSecret(secret);
    try {
      this.#secrets.set(name, bytes);
    } catch (err) {
      bytes.fill(0);
      throw err;
    }
  }

  async delete(name: string): Promise<boolean> {
    assertCredentialName(name);
    const existing = this.#secrets.get(name);
    if (existing === undefined) return false;
    existing.fill(0);
    this.#secrets.delete(name);
    return true;
  }
}

/**
 * 带超时的读取。超时后对之后才 resolve 的 SecretMaterial 立即 wipe，
 * 避免迟到明文在内存中无限停留。
 */
export async function loadSecret(
  provider: CredentialProvider,
  name: string,
  options: { timeoutMs?: number } = {},
): Promise<SecretMaterial> {
  const timeoutMs = options.timeoutMs ?? 2000;
  assertCredentialName(name);

  const lookup = provider.get(name, { timeoutMs });
  let timedOut = false;
  lookup.then(
    (secret) => {
      if (timedOut) secret.wipe();
    },
    () => undefined,
  );

  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      timedOut = true;
      reject(
        new CredentialError(
          'credential_timeout',
          `credential lookup timed out after ${timeoutMs}ms`,
        ),
      );
    }, timeoutMs);
    timer.unref?.();
  });

  try {
    return await Promise.race([lookup, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
