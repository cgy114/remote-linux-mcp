import { UsageError } from '../errors/classes.js';
import { hasLoneSurrogate, shSingleQuote } from './shell.js';

/** 远端读/写 deny 列表（均为规范化后的 "~" 或 "/" 根路径）。 */
export interface RemoteDenyLists {
  read: string[];
  write: string[];
}

/** 规范化后的远端路径。absolute 仍以 "~" 或 "/" 为根，尚未展开 $HOME。 */
export interface NormalizedRemotePath {
  raw: string;
  absolute: string;
  isHome: boolean;
}

export type RemoteAccess = 'read' | 'write';

const MAX_REMOTE_PATH_LENGTH = 4096;

/** 内置读 deny：任何用户都不得读取的位置。 */
export const BUILTIN_REMOTE_DENY_READ: readonly string[] = [
  '~/.ssh',
  '~/.gnupg',
  '~/.config/gh',
  '/etc/shadow',
  '/etc/gshadow',
  '/etc/sudoers',
  '/etc/sudoers.d',
  '/root',
  '/proc',
  '/sys',
  '/dev',
];

/** 内置写 deny：任何用户都不得写入的位置。 */
export const BUILTIN_REMOTE_DENY_WRITE: readonly string[] = [
  '/etc',
  '/bin',
  '/sbin',
  '/usr',
  '/lib',
  '/lib64',
  '/boot',
  '/root',
  '/dev',
  '/proc',
  '/sys',
  '/var/lib',
  '~/.ssh',
];

function invalid(message: string): UsageError {
  return new UsageError(message, { code: 'remote_path_invalid' });
}

function escapeError(): UsageError {
  return new UsageError('remote path escapes the filesystem root or home directory', {
    code: 'remote_path_escape',
  });
}

function assertPathText(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw invalid(`${field} must be a non-empty string`);
  }
  if (value.length > MAX_REMOTE_PATH_LENGTH) {
    throw invalid(`${field} longer than ${MAX_REMOTE_PATH_LENGTH} characters`);
  }
  if (/[\u0000\r\n]/.test(value)) {
    throw invalid(`${field} must not contain NUL, CR or LF`);
  }
  if (hasLoneSurrogate(value)) {
    throw invalid(`${field} must not contain lone UTF-16 surrogates`);
  }
  if (value.startsWith('~') && value !== '~' && !value.startsWith('~/')) {
    throw invalid(`${field} must use "~" or "~/..." (not "~user")`);
  }
  return value;
}

interface RootedParts {
  home: boolean;
  segments: string[];
}

function splitRooted(value: string): RootedParts {
  if (value[0] === '~') {
    return { home: true, segments: value.slice(1).split('/') };
  }
  return { home: false, segments: value.slice(1).split('/') };
}

function applySegments(base: RootedParts, parts: readonly string[]): RootedParts {
  const segments = [...base.segments];
  for (const part of parts) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (segments.length === 0) throw escapeError();
      segments.pop();
      continue;
    }
    segments.push(part);
  }
  return { home: base.home, segments };
}

function renderRooted(parts: RootedParts): string {
  const { home } = parts;
  const segments = parts.segments.filter((segment) => segment.length > 0);
  if (segments.length === 0) return home ? '~' : '/';
  const body = segments.join('/');
  return home ? `~/${body}` : `/${body}`;
}

function normalizeRooted(value: string): NormalizedRemotePath {
  const checked = assertPathText(value, 'remote path');
  if (checked[0] !== '/' && checked[0] !== '~') {
    throw invalid('remote path must be rooted ("/" or "~")');
  }
  const rooted = splitRooted(checked);
  const parts = applySegments({ home: rooted.home, segments: [] }, rooted.segments);
  const absolute = renderRooted(parts);
  return { raw: value, absolute, isHome: parts.home && parts.segments.length === 0 };
}

/**
 * 规范化远端路径：拒绝空/NUL/CR/LF/孤立 surrogate/>4096/"~user"；
 * 相对路径按 cwd 解析；折叠 "."/".."/"//"；越出 "/" 或 "~" 抛 remote_path_escape。
 * 返回的 absolute 仍以 "~" 或 "/" 为根（home 由 expandRemotePath 展开）。
 */
export function normalizeRemotePath(raw: string, cwd: string): NormalizedRemotePath {
  const checked = assertPathText(raw, 'remote path');
  if (checked.startsWith('/') || checked.startsWith('~')) {
    return normalizeRooted(checked);
  }
  const checkedCwd = assertPathText(cwd, 'remote cwd');
  if (!checkedCwd.startsWith('/') && !checkedCwd.startsWith('~')) {
    throw invalid('remote cwd must be rooted ("/" or "~")');
  }
  const baseParts = splitRooted(checkedCwd);
  const base = applySegments({ home: baseParts.home, segments: [] }, baseParts.segments);
  const parts = applySegments(base, checked.split('/'));
  const absolute = renderRooted(parts);
  return { raw, absolute, isHome: parts.home && parts.segments.length === 0 };
}

/** 追加 files.remoteDeny 到内置列表；内置项不可删除。去重且保持顺序。 */
export function buildRemoteDenyLists(
  files: { remoteDeny?: readonly string[] } | undefined,
): RemoteDenyLists {
  const extra = (files?.remoteDeny ?? []).map((entry) => normalizeRooted(entry).absolute);
  return {
    read: dedupe([...BUILTIN_REMOTE_DENY_READ, ...extra]),
    write: dedupe([...BUILTIN_REMOTE_DENY_WRITE, ...extra]),
  };
}

function dedupe(values: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of values) {
    if (seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
}

function stripTrailingSlash(p: string): string {
  if (p === '/' || p === '~') return p;
  let out = p;
  while (out.length > 1 && out.endsWith('/')) out = out.slice(0, -1);
  return out;
}

/** 段边界匹配：root 自身或其子路径（`/etc` 不匹配 `/etcetera`）。 */
export function isSameOrInside(root: string, candidate: string): boolean {
  const r = stripTrailingSlash(root);
  const c = stripTrailingSlash(candidate);
  if (r === c) return true;
  if (r === '/') return c.startsWith('/');
  return c.startsWith(`${r}/`);
}

function expandEntry(entry: string, home: string | undefined): string | undefined {
  if (home === undefined) return undefined;
  if (!entry.startsWith('~')) return entry;
  const normalizedHome = stripTrailingSlash(home);
  if (entry === '~') return normalizedHome;
  // home 为根时不能再拼分隔符，否则 "~/.ssh" 会变成 "//.ssh" 而无法按段匹配。
  if (normalizedHome === '/') return entry.slice(1);
  return `${normalizedHome}${entry.slice(1)}`;
}

function denial(
  candidate: NormalizedRemotePath,
  deny: readonly string[],
  home: string | undefined,
): string | undefined {
  for (const entry of deny) {
    let normalizedEntry: string;
    try {
      normalizedEntry = normalizeRooted(entry).absolute;
    } catch {
      continue;
    }
    if (isSameOrInside(normalizedEntry, candidate.absolute)) return entry;
    const expanded = expandEntry(normalizedEntry, home);
    const expandedCandidate = expandEntry(candidate.absolute, home);
    if (
      expanded !== undefined &&
      expandedCandidate !== undefined &&
      isSameOrInside(expanded, expandedCandidate)
    ) {
      return entry;
    }
  }
  return undefined;
}

/**
 * 校验路径是否被 deny 列表命中；命中抛 remote_denied_read / remote_denied_write。
 * 输入可为原始路径（内部会规范化）；home 用于把 "~" 前缀与绝对 realpath 对齐。
 */
export function assertRemotePathAllowed(
  p: string,
  access: RemoteAccess,
  deny: readonly string[],
  home?: string,
): void {
  const candidate = normalizeRooted(p);
  if (denial(candidate, deny, home) !== undefined) {
    throw denied(access);
  }
}

/** realpath 之后再次匹配：original（规范化路径）与 real（绝对路径）都不能命中 deny。 */
export function assertRemoteRealpath(
  real: string,
  original: string,
  access: RemoteAccess,
  deny: readonly string[],
  home?: string,
): void {
  const candidates = [original, real];
  for (const raw of candidates) {
    const normalized = normalizeRooted(raw);
    if (denial(normalized, deny, home) !== undefined) throw denied(access);
  }
}

function denied(access: RemoteAccess): UsageError {
  const code = access === 'read' ? 'remote_denied_read' : 'remote_denied_write';
  return new UsageError(`remote ${access} denied by policy`, { code });
}

/** 把 "~" / "~/..." 展开为 home；绝对路径原样返回。 */
export function expandRemotePath(p: string, home: string): string {
  const normalized = normalizeRooted(p).absolute;
  if (typeof home !== 'string' || home.length === 0 || home[0] !== '/') {
    throw invalid('remote home must be an absolute path');
  }
  if (home.includes('\u0000') || /[\r\n]/.test(home)) {
    throw invalid('remote home must not contain NUL, CR or LF');
  }
  const normalizedHome = stripTrailingSlash(home);
  if (normalized === '~') return normalizedHome;
  if (normalized.startsWith('~/')) {
    return normalizedHome === '/' ? normalized.slice(1) : `${normalizedHome}${normalized.slice(1)}`;
  }
  return normalized;
}

/** 远端 shell 表达式：`~` -> "$HOME"，`~/x` -> "$HOME"'/x'，绝对路径 -> 单引号。 */
export function renderRemoteShellPath(p: string): string {
  const normalized = normalizeRooted(p).absolute;
  if (normalized === '~') return '"$HOME"';
  if (normalized.startsWith('~/')) return `"$HOME"${shSingleQuote(normalized.slice(1))}`;
  return shSingleQuote(normalized);
}

/** 远端 dirname："~/a" -> "~"，"/a/b" -> "/a"，根返回自身。 */
export function dirnameRemote(p: string): string {
  const normalized = normalizeRooted(p).absolute;
  if (normalized === '/' || normalized === '~') return normalized;
  const parts = splitRooted(normalized);
  parts.segments.pop();
  return renderRooted(parts);
}

/** 远端 basename：根返回自身，其余返回最后一段。 */
export function basenameRemote(p: string): string {
  const normalized = normalizeRooted(p).absolute;
  if (normalized === '/' || normalized === '~') return normalized;
  const parts = splitRooted(normalized);
  return parts.segments[parts.segments.length - 1] ?? normalized;
}
