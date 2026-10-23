export type ConfigErrorCode = 'not_found' | 'io' | 'parse' | 'schema' | 'duplicate_key';

export class ConfigError extends Error {
  readonly code: ConfigErrorCode;
  readonly path?: string;
  readonly issues?: unknown[];

  constructor(
    code: ConfigErrorCode,
    message: string,
    options?: { path?: string; issues?: unknown[]; cause?: unknown },
  ) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'ConfigError';
    this.code = code;
    if (options?.path !== undefined) this.path = options.path;
    if (options?.issues !== undefined) this.issues = options.issues;
  }
}

export class UsageError extends Error {
  /** 机器可读的错误码（如 invalid_alias、invalid_host）；未提供时不存在。 */
  declare readonly code?: string;

  constructor(message: string, options?: { cause?: unknown; code?: string }) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'UsageError';
    if (options?.code !== undefined) this.code = options.code;
  }
}

export type TrustErrorCode =
  | 'not_registered'
  | 'fingerprint_mismatch'
  | 'known_hosts_missing'
  | 'probe_ambiguous'
  | 'lock_busy'
  | 'declined';

export class TrustError extends Error {
  readonly code: TrustErrorCode;

  constructor(code: TrustErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'TrustError';
    this.code = code;
  }
}
