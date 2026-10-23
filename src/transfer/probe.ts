import { UsageError } from '../errors/classes.js';
import { normalizeRemotePath, renderRemoteShellPath } from '../policy/remote-path.js';
import type { ToolError } from '../types.js';
import { parseSha256, remoteHashCommand } from './checksum.js';
import { runRemoteCommand, type TransferDeps } from './deps.js';
import { classifyTransportRun, remoteFailure, transferUsage } from './errors.js';
import {
  normalizeManifestEntry,
  sortManifestEntries,
  type ManifestEntry,
  type ManifestEntryType,
} from './manifest.js';

const MANIFEST_MAX_OUTPUT_BYTES = 8 * 1024 * 1024;

export interface RemotePathFacts {
  path: string;
  exists: boolean;
  type?: 'file' | 'dir' | 'symlink' | 'other';
  size?: number;
  mode?: number;
  realpath?: string;
  sha256?: string;
}

export type ProbePathResult =
  | { ok: true; facts: RemotePathFacts }
  | { ok: false; error: ToolError };

export type ProbeManifestResult =
  | { ok: true; entries: ManifestEntry[] }
  | { ok: false; error: ToolError };

export interface ProbePathOptions {
  hash?: boolean;
  realpath?: boolean;
  timeoutMs?: number;
}

export interface ProbeManifestOptions {
  maxFiles?: number;
  maxDepth?: number;
  hash?: boolean;
  timeoutMs?: number;
}

function parseError(message: string): ToolError {
  return remoteFailure('remote_manifest_failed', message);
}

function buildProbePathScript(rendered: string, opts: ProbePathOptions): string {
  const lines: string[] = [
    `p=${rendered}`,
    'if test -L "$p"; then type=symlink',
    'elif test -e "$p"; then',
    '  if test -d "$p"; then type=dir',
    '  elif test -f "$p"; then type=file',
    '  else type=other; fi',
    'else exit 3; fi',
    "statout=$(stat -c '%s %a' -- \"$p\" 2>/dev/null) || statout=$(stat -f '%z %Lp' -- \"$p\" 2>/dev/null) || statout='0 0'",
    'size=${statout%% *}',
    'mode=${statout##* }',
    'case "$size" in ""|*[!0-9]*) size=0 ;; esac',
    'case "$mode" in ""|*[!0-7]*) mode=0 ;; esac',
  ];
  if (opts.realpath === true) {
    lines.push(
      "rp=''",
      'if command -v realpath >/dev/null 2>&1; then rp=$(realpath -- "$p" 2>/dev/null) || rp=\'\'; fi',
      'if [ -z "$rp" ] && command -v readlink >/dev/null 2>&1; then rp=$(readlink -f -- "$p" 2>/dev/null) || rp=\'\'; fi',
      'if [ -n "$rp" ]; then rp="b64:$(printf \'%s\' "$rp" | base64 2>/dev/null | tr -d \'\\n\')"; fi',
      "[ -n \"$rp\" ] || rp='-'",
    );
  } else {
    lines.push("rp='-'");
  }
  if (opts.hash === true) {
    lines.push(
      "hash='-'",
      'if [ "$type" = file ]; then',
      `  hash=$({ ${remoteHashCommand('"$p"')}; } | grep -o -E '[0-9a-fA-F]{64}' 2>/dev/null | head -n 1)`,
      '  if [ -z "$hash" ]; then hash="-"; fi',
      'fi',
    );
  } else {
    lines.push("hash='-'");
  }
  lines.push("printf '%s\\t%s\\t%s\\t%s\\t%s\\n' \"$type\" \"$size\" \"$mode\" \"$rp\" \"$hash\"");
  return lines.join('\n');
}

function decodeBase64Field(field: string): string | undefined {
  if (field === '' || field === '-') return undefined;
  if (!field.startsWith('b64:')) return field;
  const encoded = field.slice(4);
  if (encoded === '') return undefined;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || encoded.length % 4 !== 0) return undefined;
  const buf = Buffer.from(encoded, 'base64');
  if (buf.toString('base64') !== encoded) return undefined;
  return buf.toString('utf8');
}

/** 探测单个远端路径：test -L 优先，stat -c/stat -f 回退，可选 hash/realpath。 */
export async function probeRemotePath(
  deps: TransferDeps,
  rawPath: string,
  opts: ProbePathOptions = {},
): Promise<ProbePathResult> {
  let normalized;
  try {
    normalized = normalizeRemotePath(rawPath, deps.target.host.cwd);
  } catch (err) {
    if (err instanceof UsageError) {
      return { ok: false, error: transferUsage(err.code ?? 'remote_path_invalid', err.message) };
    }
    return { ok: false, error: transferUsage('remote_path_invalid', String(err)) };
  }
  const script = buildProbePathScript(renderRemoteShellPath(normalized.absolute), opts);
  const run = await runRemoteCommand(deps, script, {
    ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    label: `probe:${deps.target.host.alias}`,
  });

  if (run.exitCode === 3 && run.stdout.trim() === '') {
    return { ok: true, facts: { path: normalized.absolute, exists: false } };
  }
  const failure = classifyTransportRun(run, { label: 'probe' });
  if (failure !== undefined) return { ok: false, error: failure };

  const lines = run.stdout.split(/\r?\n/).filter((line) => line.trim().length > 0);
  if (lines.length !== 1) {
    return { ok: false, error: parseError('remote path probe output is malformed') };
  }
  const fields = lines[0]!.split('\t');
  if (fields.length !== 5) {
    return { ok: false, error: parseError('remote path probe returned an unexpected field count') };
  }
  const typeText = fields[0]!;
  const type =
    typeText === 'file' || typeText === 'dir' || typeText === 'symlink' || typeText === 'other'
      ? typeText
      : undefined;
  if (type === undefined) {
    return { ok: false, error: parseError('remote path probe returned an unknown type') };
  }
  const sizeText = fields[1]!;
  const modeText = fields[2]!;
  if (!/^\d+$/.test(sizeText) || !/^[0-7]+$/.test(modeText)) {
    return { ok: false, error: parseError('remote path probe returned invalid size/mode') };
  }
  const facts: RemotePathFacts = {
    path: normalized.absolute,
    exists: true,
    type,
    size: Number(sizeText),
    mode: Number.parseInt(modeText, 8),
  };
  const realpath = decodeBase64Field(fields[3]!);
  if (realpath !== undefined) facts.realpath = realpath;
  const hashText = fields[4]!;
  if (hashText !== '' && hashText !== '-') {
    const sha = parseSha256(hashText);
    if (sha !== undefined) facts.sha256 = sha;
  }
  return { ok: true, facts };
}

function buildManifestScript(
  renderedRoot: string,
  opts: ProbeManifestOptions,
): string {
  const maxDepth = opts.maxDepth ?? 64;
  const hashEnabled = opts.hash !== false;
  const hashLine = hashEnabled
    ? `  if [ "$type" = file ]; then hash=$({ ${remoteHashCommand('"$f"')}; } | grep -o -E "[0-9a-fA-F]{64}" 2>/dev/null | head -n 1); fi`
    : '  hash=""';
  return [
    `root=${renderedRoot}`,
    'find "$root" -mindepth 1 -maxdepth ' + String(maxDepth) + " -exec sh -c '",
    'root=$1; shift',
    'for f do',
    '  if test -L "$f"; then type=symlink',
    '  elif test -d "$f"; then type=dir',
    '  elif test -f "$f"; then type=file',
    '  else type=other; fi',
    '  statout=$(stat -c "%s %a" -- "$f" 2>/dev/null) || statout=$(stat -f "%z %Lp" -- "$f" 2>/dev/null) || statout="0 0"',
    '  size=${statout%% *}',
    '  mode=${statout##* }',
    '  case "$size" in ""|*[!0-9]*) size=0 ;; esac',
    '  case "$mode" in ""|*[!0-7]*) mode=0 ;; esac',
    '  if [ "$type" = dir ] || [ "$type" = symlink ]; then size=0; fi',
    '  rel=${f#"$root"/}',
    '  case "$f" in "$root"/*) ;; *) rel=${f#"$root"}; rel=${rel#/} ;; esac',
    '  relb64=$(printf "%s" "$rel" | base64 2>/dev/null | tr -d "\\n")',
    '  if [ -n "$relb64" ]; then relb64="b64:$relb64"; fi',
    '  hash=""',
    hashLine,
    '  link=""',
    '  if [ "$type" = symlink ]; then',
    '    link=$(readlink -- "$f" 2>/dev/null) || link=""',
    '    if [ -n "$link" ]; then link="b64:$(printf "%s" "$link" | base64 2>/dev/null | tr -d "\\n")"; fi',
    '  fi',
    "  printf \"%s\\t%s\\t%s\\t%s\\t%s\\t%s\\000\" \"$type\" \"$size\" \"$mode\" \"$relb64\" \"$hash\" \"$link\"",
    'done',
    "' sh \"$root\" {} +",
  ].join('\n');
}

/** 探测远端目录清单（find + hash）；限制 maxFiles，解析失败归为 remote_manifest_failed。 */
export async function probeRemoteManifest(
  deps: TransferDeps,
  rawRoot: string,
  opts: ProbeManifestOptions = {},
): Promise<ProbeManifestResult> {
  let normalized;
  try {
    normalized = normalizeRemotePath(rawRoot, deps.target.host.cwd);
  } catch (err) {
    if (err instanceof UsageError) {
      return { ok: false, error: transferUsage(err.code ?? 'remote_path_invalid', err.message) };
    }
    return { ok: false, error: transferUsage('remote_path_invalid', String(err)) };
  }
  const maxFiles = opts.maxFiles;
  const script = buildManifestScript(renderRemoteShellPath(normalized.absolute), opts);
  const run = await runRemoteCommand(deps, script, {
    maxOutputBytes: MANIFEST_MAX_OUTPUT_BYTES,
    ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    label: `manifest:${deps.target.host.alias}`,
  });

  const failure = classifyTransportRun(run, { label: 'manifest' });
  if (failure !== undefined) return { ok: false, error: failure };

  const records = run.stdout.split('\u0000');
  const entries: ManifestEntry[] = [];
  for (const record of records) {
    if (record.length === 0) continue;
    const fields = record.split('\t');
    if (fields.length !== 6) {
      return { ok: false, error: parseError('remote manifest output has an unexpected field count') };
    }
    const typeText = fields[0]!;
    if (typeText === 'other') continue;
    if (typeText !== 'file' && typeText !== 'dir' && typeText !== 'symlink') {
      return { ok: false, error: parseError('remote manifest returned an unknown entry type') };
    }
    const sizeText = fields[1]!;
    const modeText = fields[2]!;
    if (!/^\d+$/.test(sizeText) || !/^[0-7]+$/.test(modeText)) {
      return { ok: false, error: parseError('remote manifest returned invalid size/mode') };
    }
    const rel = decodeBase64Field(fields[3]!);
    if (rel === undefined || rel === '') {
      return { ok: false, error: parseError('remote manifest returned an invalid path') };
    }
    const hashText = fields[4]!;
    const linkText = decodeBase64Field(fields[5]!);
    const entry: ManifestEntry = {
      path: rel,
      type: typeText as ManifestEntryType,
      size: Number(sizeText),
      mode: Number.parseInt(modeText, 8),
    };
    if (hashText !== '') {
      const sha = parseSha256(hashText);
      if (sha === undefined) {
        return { ok: false, error: parseError('remote manifest returned an invalid sha256') };
      }
      entry.sha256 = sha;
    }
    if (linkText !== undefined) entry.linkTarget = linkText;
    try {
      entries.push(normalizeManifestEntry(entry));
    } catch {
      return { ok: false, error: parseError('remote manifest entry is invalid') };
    }
    if (maxFiles !== undefined && entries.length > maxFiles) {
      return {
        ok: false,
        error: transferUsage(
          'too_many_files',
          `remote manifest has more than ${maxFiles} entries`,
        ),
      };
    }
  }
  return { ok: true, entries: sortManifestEntries(entries) };
}

const homeCache = new WeakMap<TransferDeps, Promise<string>>();

function invalidHome(): UsageError {
  return new UsageError('cannot determine the remote home directory', {
    code: 'remote_manifest_failed',
  });
}

/**
 * 解析远端 home（`printf %s "$HOME"`），按 TransferDeps 缓存。
 * 结果必须是绝对路径；失败抛 remote_manifest_failed。
 */
export function resolveRemoteHome(deps: TransferDeps): Promise<string> {
  if (deps.home !== undefined) return Promise.resolve(deps.home);
  const cached = homeCache.get(deps);
  if (cached !== undefined) return cached;
  const pending = (async (): Promise<string> => {
    const run = await runRemoteCommand(deps, "printf '%s' \"$HOME\"", {
      label: `home:${deps.target.host.alias}`,
    });
    const failure = classifyTransportRun(run, { label: 'home' });
    if (failure !== undefined) {
      throw new UsageError(failure.message, { code: 'remote_manifest_failed' });
    }
    const value = run.stdout.replace(/\r?\n$/, '');
    if (value.length === 0 || value[0] !== '/' || /[\r\n\u0000]/.test(value)) {
      throw invalidHome();
    }
    return value;
  })();
  homeCache.set(deps, pending);
  pending.catch(() => homeCache.delete(deps));
  return pending;
}
