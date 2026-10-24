import { z } from 'zod';
import { ConfigError } from '../errors/classes.js';
import { assertRemoteCwd } from '../policy/remote-command.js';
import type { Defaults, FilesConfig } from '../types.js';

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

/**
 * 远端 cwd 的配置侧格式校验：与 assertRemoteCwd 完全一致
 * （以 `/` 或 `~` 开头、拒绝 `~user`、≤4096、无 NUL/CR/LF/孤立 surrogate）。
 * 在加载期以 ConfigError('schema') 暴露，而不是等到首次执行才失败。
 */
const cwdSchema = z.string().min(1).superRefine((value, ctx) => {
  try {
    assertRemoteCwd(value);
  } catch (err) {
    ctx.addIssue({
      code: 'custom',
      message: err instanceof Error ? err.message : 'invalid remote cwd',
    });
  }
});

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
  default_cwd: cwdSchema.optional(),
  default_host: aliasSchema.optional(),
  timeouts: timeoutsSchema.optional(),
  max_output_bytes: z.number().int().min(4096).max(8388608).optional(),
  sudo: sudoSchema.optional(),
});

const securitySchema = z.strictObject({
  host_key_policy: z.literal('pinned').optional(),
  known_hosts_file: z.string().min(1).optional(),
});

/** P3 文件策略的默认门限。 */
const DEFAULT_MAX_FILE_BYTES = 512 * 1024 * 1024; // 512 MiB
const DEFAULT_MAX_FILES = 10_000;
const DEFAULT_MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024; // 4 GiB
const DEFAULT_MAX_DEPTH = 64;
const DEFAULT_TRANSFER_TIMEOUT_MS = 300_000;

/** remote_deny 条目：以 / 或 ~ 开头、无 NUL、不含 ".." 段。 */
const remoteDenySchema = z.string().min(1).superRefine((value, ctx) => {
  if (value[0] !== '/' && value[0] !== '~') {
    ctx.addIssue({ code: 'custom', message: 'remote_deny entries must start with "/" or "~"' });
    return;
  }
  if (value.includes('\u0000')) {
    ctx.addIssue({ code: 'custom', message: 'remote_deny entries must not contain NUL' });
  }
  if (value.split('/').some((segment) => segment === '..')) {
    ctx.addIssue({ code: 'custom', message: 'remote_deny entries must not contain ".." segments' });
  }
});

/** files 段：严格对象；max_file_bytes 不得超过 max_total_bytes（按展开后的默认值比较）。 */
export const filesSchema = z
  .strictObject({
    local_roots: z.array(z.string().min(1)).optional(),
    remote_deny: z.array(remoteDenySchema).optional(),
    max_file_bytes: positiveIntSchema.optional(),
    max_files: positiveIntSchema.optional(),
    max_total_bytes: positiveIntSchema.optional(),
    max_depth: z.number().int().min(0).optional(),
    transfer_timeout_ms: positiveIntSchema.optional(),
  })
  .superRefine((files, ctx) => {
    const maxFile = files.max_file_bytes ?? DEFAULT_MAX_FILE_BYTES;
    const maxTotal = files.max_total_bytes ?? DEFAULT_MAX_TOTAL_BYTES;
    if (maxFile > maxTotal) {
      ctx.addIssue({
        code: 'custom',
        path: ['max_file_bytes'],
        message: 'max_file_bytes must not exceed max_total_bytes',
      });
    }
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
  default_cwd: cwdSchema.optional(),
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
  files: filesSchema.optional(),
  hosts: z
    .record(aliasSchema, hostSchema)
    .refine((h) => Object.keys(h).length > 0, { message: 'at least one host is required' }),
});

export type RawConfig = z.infer<typeof configSchema>;

export interface DefaultsForOptions {
  /** 把 local_roots 条目解析为绝对路径（loadConfig 用于 "~" 展开与 baseDir 解析）。 */
  resolveLocalRoot?: (p: string) => string;
}

/**
 * 展开 files 段的默认值：512 MiB 单文件 / 10000 个文件 / 4 GiB 总量 /
 * 深度 64 / 传输超时 300s。校验策略是 P3 不变量（manifest），不可配置。
 * local_roots 可注入路径解析器。
 */
export function filesFor(
  raw: RawConfig,
  resolveLocalRoot?: (p: string) => string,
): FilesConfig {
  const f = raw.files;
  return {
    localRoots: (f?.local_roots ?? []).map((p) =>
      resolveLocalRoot !== undefined ? resolveLocalRoot(p) : p,
    ),
    remoteDeny: [...(f?.remote_deny ?? [])],
    maxFileBytes: f?.max_file_bytes ?? DEFAULT_MAX_FILE_BYTES,
    maxFiles: f?.max_files ?? DEFAULT_MAX_FILES,
    maxTotalBytes: f?.max_total_bytes ?? DEFAULT_MAX_TOTAL_BYTES,
    maxDepth: f?.max_depth ?? DEFAULT_MAX_DEPTH,
    transferTimeoutMs: f?.transfer_timeout_ms ?? DEFAULT_TRANSFER_TIMEOUT_MS,
  };
}

/** 展开 defaults 段的全部默认值（port 22 / default_cwd "~" / 超时 5000,15000,8000 / 输出 1MiB / sudo off / files 默认）。 */
export function defaultsFor(raw: RawConfig, opts?: DefaultsForOptions): Defaults {
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
    files: filesFor(raw, opts?.resolveLocalRoot),
  };
  if (defaultHost !== undefined) defaults.defaultHost = defaultHost;
  return defaults;
}
