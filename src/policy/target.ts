import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { ConfigError } from '../errors/classes.js';
import type {
  Alias,
  EffectiveHost,
  ErrorFacts,
  HostConfig,
  JumpSpec,
  KnownHostEntry,
  PinnedHostKey,
  RemoteConfig,
  Target,
  TrustRegistry,
} from '../types.js';
import { assertAlias, usageError } from './alias.js';

const MAX_JUMPS = 3;
const HOST_MAX_LENGTH = 255;
const USER_RE = /^(?!-)[A-Za-z0-9._-]{1,64}$/;
const CWD_MAX_LENGTH = 4096;
// whitespace, C0/DEL control characters, and the separators "@" and "/"
const HOST_FORBIDDEN_RE = /[\s\u0000-\u001f\u007f@/]/;
// NUL, CR, LF
const CWD_FORBIDDEN_RE = /[\u0000\r\n]/;
const JUMP_PORT_RE = /^\d{1,5}$/;
const IPV6_BODY_RE = /^[0-9A-Fa-f:.]+$/;

export function assertHostString(v: unknown): string {
  if (typeof v !== 'string' || v.length === 0) {
    throw usageError('invalid_host', 'host must be a non-empty string');
  }
  if (v.length > HOST_MAX_LENGTH) {
    throw usageError('invalid_host', `host longer than ${HOST_MAX_LENGTH} characters`);
  }
  if (HOST_FORBIDDEN_RE.test(v)) {
    throw usageError('invalid_host', 'host must not contain whitespace, control characters, "@" or "/"');
  }
  if (v.startsWith('-')) {
    throw usageError('invalid_host', 'host must not start with "-"');
  }
  return v;
}

export function assertUser(v: unknown): string {
  if (typeof v !== 'string' || !USER_RE.test(v)) {
    throw usageError('invalid_user', `invalid user ${JSON.stringify(v)} (must match ${USER_RE.source})`);
  }
  return v;
}

export function assertPort(v: unknown): number {
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 1 || v > 65535) {
    throw usageError('invalid_port', `invalid port ${JSON.stringify(v)} (must be an integer 1-65535)`);
  }
  return v;
}

export function assertCwd(v: unknown): string {
  if (typeof v !== 'string' || (v[0] !== '/' && v[0] !== '~')) {
    throw usageError('invalid_cwd', 'remote cwd must start with "/" or "~"');
  }
  if (v.length > CWD_MAX_LENGTH) {
    throw usageError('invalid_cwd', `remote cwd longer than ${CWD_MAX_LENGTH} characters`);
  }
  if (CWD_FORBIDDEN_RE.test(v)) {
    throw usageError('invalid_cwd', 'remote cwd must not contain NUL or newline characters');
  }
  return v;
}

export function assertTarget({
  user,
  host,
  port,
  jumps,
}: {
  user: string;
  host: string;
  port: number;
  jumps: JumpSpec[];
}): Target {
  assertUser(user);
  assertHostString(host);
  assertPort(port);
  if (!Array.isArray(jumps) || jumps.length > MAX_JUMPS) {
    throw usageError('invalid_jump', `at most ${MAX_JUMPS} jump hosts are allowed`);
  }
  const checked: JumpSpec[] = jumps.map((j) => {
    if (j.user !== undefined) assertUser(j.user);
    assertHostString(j.host);
    if (j.port !== undefined) assertPort(j.port);
    return { ...j };
  });
  return { destination: `${user}@${host}`, jumps: checked };
}

/**
 * Parses a ProxyJump-style string ("a,user@b:2222,[::1]:22") into jump specs.
 * `undefined` means no jump hosts; an empty string is an error.
 */
export function selectJumpSpec(
  proxyJump?: string,
  defaults?: { user?: string; port?: number },
): JumpSpec[] {
  if (proxyJump === undefined) return [];
  const parts = proxyJump.split(',');
  if (parts.length > MAX_JUMPS) {
    throw usageError('invalid_jump', `at most ${MAX_JUMPS} jump hosts are allowed`);
  }
  const defaultPort = defaults?.port ?? 22;
  const defaultUser = defaults?.user;
  return parts.map((part) => parseJump(part, defaultPort, defaultUser));
}

function parseJump(raw: string, defaultPort: number, defaultUser: string | undefined): JumpSpec {
  if (raw.length === 0) {
    throw usageError('invalid_jump', 'empty jump host element');
  }

  let user: string | undefined;
  let rest = raw;
  const at = raw.indexOf('@');
  if (at !== -1) {
    const candidate = raw.slice(0, at);
    if (!USER_RE.test(candidate)) {
      throw usageError('invalid_jump', `invalid user in jump host ${JSON.stringify(raw)}`);
    }
    user = candidate;
    rest = raw.slice(at + 1);
  }

  let host: string;
  let port: number | undefined;
  if (rest.startsWith('[')) {
    const close = rest.indexOf(']');
    if (close === -1) {
      throw usageError('invalid_jump', `unterminated "[" in jump host ${JSON.stringify(raw)}`);
    }
    host = rest.slice(1, close);
    if (!IPV6_BODY_RE.test(host) || !host.includes(':')) {
      throw usageError('invalid_jump', `invalid IPv6 address in jump host ${JSON.stringify(raw)}`);
    }
    const after = rest.slice(close + 1);
    if (after !== '') {
      if (!after.startsWith(':')) {
        throw usageError('invalid_jump', `unexpected characters after "]" in ${JSON.stringify(raw)}`);
      }
      port = parseJumpPort(after.slice(1), raw);
    }
  } else {
    const firstColon = rest.indexOf(':');
    if (firstColon !== -1 && rest.indexOf(':', firstColon + 1) !== -1) {
      throw usageError('invalid_jump', `IPv6 jump host must be bracketed: ${JSON.stringify(raw)}`);
    }
    if (firstColon === -1) {
      host = rest;
    } else {
      host = rest.slice(0, firstColon);
      port = parseJumpPort(rest.slice(firstColon + 1), raw);
    }
  }

  try {
    assertHostString(host);
  } catch (cause) {
    throw usageError('invalid_jump', `invalid jump host ${JSON.stringify(raw)}`, { cause });
  }

  const resolvedUser = user ?? defaultUser;
  const spec: JumpSpec = { host, port: port ?? defaultPort };
  if (resolvedUser !== undefined) spec.user = resolvedUser;
  return spec;
}

function parseJumpPort(s: string, raw: string): number {
  if (!JUMP_PORT_RE.test(s)) {
    throw usageError('invalid_jump', `invalid port in jump host ${JSON.stringify(raw)}`);
  }
  const n = Number(s);
  if (n < 1 || n > 65535) {
    throw usageError('invalid_jump', `port out of range in jump host ${JSON.stringify(raw)}`);
  }
  return n;
}

/**
 * Resolves an identityFile path: "~" expands to the current user's home only
 * (no "~other"), relative paths are resolved against baseDir.
 */
export function resolveIdentityFile(p: string | undefined, baseDir: string): string | undefined {
  if (p === undefined) return undefined;
  if (p.includes('\u0000')) {
    throw new ConfigError('schema', 'identityFile contains a NUL byte');
  }
  if (p.length === 0) {
    throw new ConfigError('schema', 'identityFile must not be empty');
  }
  let expanded = p;
  if (p === '~' || p.startsWith('~/') || p.startsWith('~\\')) {
    expanded = path.join(os.homedir(), p.slice(1));
  } else if (p.startsWith('~')) {
    throw new ConfigError('schema', 'identityFile only supports "~" for the current user, not "~user"');
  }
  return path.resolve(baseDir, expanded);
}

export function effectiveHost(cfg: RemoteConfig, alias: string): EffectiveHost {
  const a = assertAlias(alias);
  const h: HostConfig | undefined = Object.prototype.hasOwnProperty.call(cfg.hosts, a)
    ? cfg.hosts[a]
    : undefined;
  if (!h) {
    throw usageError('unknown_alias', `unknown host alias: ${a}`);
  }
  const d = cfg.defaults;
  const eff: EffectiveHost = {
    alias: a,
    host: h.host,
    user: h.user,
    port: h.port ?? d.port,
    cwd: h.defaultCwd ?? d.defaultCwd,
    timeouts: { ...d.timeouts },
    maxOutputBytes: d.maxOutputBytes,
    sudo: { ...d.sudo, allow: [...d.sudo.allow], deny: [...d.sudo.deny] },
  };
  const identityFile = resolveIdentityFile(h.identityFile, cfg.baseDir);
  if (identityFile !== undefined) eff.identityFile = identityFile;
  if (h.proxyJump !== undefined) eff.proxyJump = h.proxyJump;
  return eff;
}

export function describeHost(h: EffectiveHost): string {
  const via = h.proxyJump !== undefined && h.proxyJump !== '' ? `, via ${h.proxyJump}` : '';
  return `${h.alias} (${h.user}@${h.host}:${h.port}${via})`;
}

export type TrustCheck =
  | { ok: true; pinned: PinnedHostKey }
  | { ok: false; fact: Partial<ErrorFacts> };

/**
 * Checks that the pinned fingerprint for `alias` is present in known_hosts for
 * the host/port. Revoked and cert-authority lines never count as a match.
 * Does not throw: any unexpected failure fails closed as fingerprint_mismatch.
 */
export function checkTrustState(input: {
  alias: Alias;
  host: EffectiveHost;
  registry: TrustRegistry;
  knownHosts: KnownHostEntry[];
}): TrustCheck {
  try {
    const { alias, host, registry, knownHosts } = input;
    const pinned: PinnedHostKey | undefined = Object.prototype.hasOwnProperty.call(registry.hosts, alias)
      ? registry.hosts[alias]
      : undefined;
    if (!pinned) {
      return { ok: false, fact: { reason: 'not_registered' } };
    }

    const names = hostNames(host.host, host.port);
    const entries = knownHosts.filter(
      (e) => e.marker === null && e.hosts.some((n) => names.has(n.toLowerCase())),
    );
    if (entries.length === 0) {
      return { ok: false, fact: { reason: 'known_hosts_missing' } };
    }

    const matched = entries.some((e) => fingerprintKey(e.keyBlob) === pinned.fingerprint);
    if (matched) {
      return { ok: true, pinned };
    }
    return { ok: false, fact: { reason: 'fingerprint_mismatch' } };
  } catch {
    return { ok: false, fact: { reason: 'fingerprint_mismatch' } };
  }
}

function hostNames(host: string, port: number): Set<string> {
  const h = host.toLowerCase();
  const names = new Set<string>([`[${h}]:${port}`]);
  if (port === 22) names.add(h);
  return names;
}

/** OpenSSH-style SHA256 fingerprint of a base64 public key blob. */
function fingerprintKey(keyBlob: string): string {
  const digest = createHash('sha256')
    .update(Buffer.from(keyBlob, 'base64'))
    .digest('base64')
    .replace(/=+$/, '');
  return `SHA256:${digest}`;
}
