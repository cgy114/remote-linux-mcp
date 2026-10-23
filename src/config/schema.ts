import { z } from 'zod';
import { ConfigError } from '../errors/classes.js';
import type { Defaults } from '../types.js';

/** host alias：小写字母数字开头，后续允许 . _ -，最长 64。 */
const ALIAS_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
/** 保留字：不能作为 host alias（与 CLI 子命令 / 内部名冲突）。 */
const RESERVED_ALIASES: ReadonlySet<string> = new Set(['default', 'serve', 'trust']);
/** host：非空、≤255、无空白/控制字符、不以 - 开头、不含 @ 和 /。 */
const HOST_RE = /^(?!-)[^\s\p{Cc}@/]+$/u;
const HOST_MAX_LENGTH = 255;
/** user：首字符不能是 "-"，与 policy/alias 的 assertUser 保持一致。 */
const USER_RE = /^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$/;

const portSchema = z.number().int().min(1).max(65535);
const positiveIntSchema = z.number().int().positive();

export const aliasSchema = z
  .string()
  .regex(ALIAS_RE, { message: 'host alias must match ^[a-z0-9][a-z0-9._-]{0,63}$' })
  .refine((k) => !RESERVED_ALIASES.has(k), { message: 'host alias is reserved (default/serve/trust)' });

const timeoutsSchema = z.strictObject({
  connect_ms: positiveIntSchema.optional(),
  command_ms: positiveIntSchema.optional(),
  check_ms: positiveIntSchema.optional(),
});

const sudoSchema = z.strictObject({
  mode: z.enum(['off', 'passwordless', 'password']).optional(),
  credential: z.string().optional(),
  allow: z.array(z.string()).optional(),
  deny: z.array(z.string()).optional(),
});

const defaultsSchema = z.strictObject({
  port: portSchema.optional(),
  default_cwd: z.string().min(1).optional(),
  default_host: aliasSchema.optional(),
  timeouts: timeoutsSchema.optional(),
  max_output_bytes: z.number().int().min(4096).max(8388608).optional(),
  sudo: sudoSchema.optional(),
});

const securitySchema = z.strictObject({
  host_key_policy: z.literal('pinned').optional(),
  known_hosts_file: z.string().min(1).optional(),
});

const hostSchema = z.strictObject({
  host: z
    .string()
    .max(HOST_MAX_LENGTH, { message: `host must be at most ${HOST_MAX_LENGTH} characters` })
    .regex(HOST_RE, {
      message: 'host must be non-empty and at most 255 characters, without whitespace/control chars, "@" or "/", and not start with "-"',
    }),
  user: z.string().regex(USER_RE, { message: 'user must match ^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$' }),
  port: portSchema.optional(),
  identity_file: z.string().min(1).optional(),
  proxy_jump: z.string().optional(),
  default_cwd: z.string().min(1).optional(),
  description: z.string().optional(),
});

/**
 * 原始配置（snake_case，与 YAML 键一致）。可选字段的默认值由 defaultsFor 展开，
 * loadConfig 再转换为 camelCase 的 RemoteConfig。
 */
export const configSchema = z.strictObject({
  version: z.literal(1),
  defaults: defaultsSchema.optional(),
  security: securitySchema.optional(),
  hosts: z
    .record(aliasSchema, hostSchema)
    .refine((h) => Object.keys(h).length > 0, { message: 'at least one host is required' }),
});

export type RawConfig = z.infer<typeof configSchema>;

/** 展开 defaults 段的全部默认值（port 22 / default_cwd "~" / 超时 5000,15000,8000 / 输出 1MiB / sudo off）。 */
export function defaultsFor(raw: RawConfig): Defaults {
  const d = raw.defaults;
  const t = d?.timeouts;
  const s = d?.sudo;
  const sudo: Defaults['sudo'] = {
    mode: s?.mode ?? 'off',
    allow: [...(s?.allow ?? [])],
    deny: [...(s?.deny ?? [])],
  };
  if (s?.credential !== undefined) sudo.credential = s.credential;

  const defaultHost = d?.default_host;
  if (defaultHost !== undefined && !Object.prototype.hasOwnProperty.call(raw.hosts, defaultHost)) {
    throw new ConfigError('schema', `defaults.default_host "${defaultHost}" is not defined in hosts`);
  }

  const defaults: Defaults = {
    port: d?.port ?? 22,
    defaultCwd: d?.default_cwd ?? '~',
    timeouts: {
      connectMs: t?.connect_ms ?? 5000,
      commandMs: t?.command_ms ?? 15000,
      checkMs: t?.check_ms ?? 8000,
    },
    maxOutputBytes: d?.max_output_bytes ?? 1048576,
    sudo,
  };
  if (defaultHost !== undefined) defaults.defaultHost = defaultHost;
  return defaults;
}
