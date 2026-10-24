import { randomBytes } from 'node:crypto';
import { promises as fs, type Stats } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { UsageError } from '../errors/classes.js';
import {
  assertDepth,
  assertFileCount,
  assertFileSize,
  assertTotalBytes,
  type FileLimits,
} from './file-policy.js';
import { sortManifestEntries, type ManifestEntry } from './manifest.js';

const IS_WIN = process.platform === 'win32';

export type LocalKind = 'file' | 'dir';

export interface LocalPathRoots {
  /** 白名单根目录（已解析为绝对路径）。 */
  roots: readonly string[];
  /** 测试可注入的 home（默认 os.homedir()）。 */
  home?: string;
}

function localUsage(code: string, message: string): UsageError {
  return new UsageError(message, { code });
}

/** `~` / `~/...` 展开；`~user` 拒绝。 */
export function expandLocalPath(raw: string, home: string): string {
  if (raw === '~') return home;
  if (raw.startsWith('~/') || raw.startsWith('~\\')) return path.join(home, raw.slice(2));
  if (raw.startsWith('~')) {
    throw localUsage('local_path_invalid', 'only "~" and "~/..." are supported (not "~user")');
  }
  return raw;
}

function assertLocalPathText(raw: unknown): string {
  if (typeof raw !== 'string' || raw.length === 0) {
    throw localUsage('local_path_invalid', 'local path must be a non-empty string');
  }
  if (raw.includes('\u0000')) {
    throw localUsage('local_path_invalid', 'local path must not contain a NUL byte');
  }
  return raw;
}

function preparePath(raw: string, home: string): string {
  return path.resolve(expandLocalPath(assertLocalPathText(raw), home));
}

function foldLocal(p: string): string {
  return IS_WIN ? p.toLowerCase() : p;
}

/** 候选路径是否位于 root 之内（含 root 自身）；Windows 大小写折叠。 */
export function isLocalContained(root: string, candidate: string): boolean {
  const r = path.resolve(root);
  const c = path.resolve(candidate);
  const rel = path.relative(foldLocal(r), foldLocal(c));
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel));
}

interface ResolvedRoots {
  lexical: string[];
  real: string[];
}

async function resolveRoots(roots: readonly string[]): Promise<ResolvedRoots> {
  const lexical = roots.map((root) => path.resolve(root));
  const real = await Promise.all(
    lexical.map(async (root) => {
      try {
        return await fs.realpath(root);
      } catch {
        return root;
      }
    }),
  );
  return { lexical, real };
}

/** 候选路径不在任何白名单 root 内时抛 local_root_not_allowed。 */
function assertContainedInAny(roots: ResolvedRoots, candidate: string): void {
  for (let i = 0; i < roots.lexical.length; i++) {
    const lexical = roots.lexical[i]!;
    const real = roots.real[i]!;
    if (isLocalContained(lexical, candidate) || isLocalContained(real, candidate)) return;
  }
  throw localUsage('local_root_not_allowed', 'local path is outside the allowed roots');
}

function lstatError(err: unknown, missingCode: string, what: string): UsageError {
  const code =
    typeof err === 'object' && err !== null && 'code' in err
      ? String((err as { code?: unknown }).code)
      : 'IO_ERROR';
  if (code === 'ENOENT') {
    return localUsage(missingCode, `${what} does not exist`);
  }
  return localUsage('local_io_error', `cannot stat ${what}: ${code}`);
}

export interface ResolveLocalSourceInput extends LocalPathRoots {
  path: string;
  limits: FileLimits;
  /** 允许目录（目录下载/上传）；默认只允许普通文件。 */
  allowDir?: boolean;
}

export interface LocalSource {
  /** path.resolve 之后的请求路径。 */
  path: string;
  realPath: string;
  kind: LocalKind;
  size: number;
  mode: number;
  stat: Stats;
}

/** 解析本地源：~ 展开 -> lstat（拒绝 symlink）-> 类型/大小 -> realpath 白名单。 */
export async function resolveLocalSource(input: ResolveLocalSourceInput): Promise<LocalSource> {
  const home = input.home ?? os.homedir();
  const abs = preparePath(input.path, home);
  let stat: Stats;
  try {
    stat = await fs.lstat(abs);
  } catch (err) {
    throw lstatError(err, 'local_source_not_found', 'local source');
  }
  if (stat.isSymbolicLink()) {
    throw localUsage('local_symlink', 'local source must not be a symbolic link');
  }
  let kind: LocalKind;
  if (stat.isDirectory()) {
    if (input.allowDir !== true) {
      throw localUsage('local_invalid_type', 'local source is a directory; a file is required');
    }
    kind = 'dir';
  } else if (stat.isFile()) {
    kind = 'file';
  } else {
    throw localUsage('local_invalid_type', 'local source must be a regular file or directory');
  }
  if (kind === 'file') assertFileSize(stat.size, input.limits, 'local source');

  let realPath: string;
  try {
    realPath = await fs.realpath(abs);
  } catch (err) {
    throw lstatError(err, 'local_source_not_found', 'local source');
  }
  const roots = await resolveRoots(input.roots);
  assertContainedInAny(roots, realPath);
  assertContainedInAny(roots, abs);

  return { path: abs, realPath, kind, size: stat.size, mode: stat.mode & 0o777, stat };
}

export interface ResolveLocalTargetInput extends LocalPathRoots {
  path: string;
  limits: FileLimits;
  /** 允许目标是目录（目录下载）；默认只允许文件。 */
  allowDir?: boolean;
  /** 目标已存在时是否允许覆盖；默认 false。 */
  overwrite?: boolean;
}

export interface LocalTarget {
  path: string;
  exists: boolean;
  realPath?: string;
  kind?: LocalKind;
  size?: number;
  mode?: number;
}

/**
 * 解析本地目标：父目录必须存在且在白名单内；目标自身不得是 symlink；
 * 已存在且 overwrite=false 时抛 target_exists。
 */
export async function resolveLocalTarget(input: ResolveLocalTargetInput): Promise<LocalTarget> {
  const home = input.home ?? os.homedir();
  const abs = preparePath(input.path, home);
  const parent = path.dirname(abs);

  let stat: Stats | undefined;
  try {
    stat = await fs.lstat(abs);
  } catch (err) {
    const code =
      typeof err === 'object' && err !== null && 'code' in err
        ? String((err as { code?: unknown }).code)
        : 'IO_ERROR';
    if (code !== 'ENOENT') {
      throw localUsage('local_io_error', `cannot stat local target: ${code}`);
    }
  }

  let parentStat: Stats;
  try {
    parentStat = await fs.stat(parent);
  } catch (err) {
    throw lstatError(err, 'local_parent_missing', 'local target parent');
  }
  if (!parentStat.isDirectory()) {
    throw localUsage('local_parent_not_directory', 'local target parent is not a directory');
  }

  let kind: LocalKind | undefined;
  if (stat !== undefined) {
    if (stat.isSymbolicLink()) {
      throw localUsage('local_symlink', 'local target must not be a symbolic link');
    }
    if (stat.isDirectory()) {
      if (input.allowDir !== true) {
        throw localUsage('local_invalid_type', 'local target is a directory; a file is required');
      }
      kind = 'dir';
    } else if (stat.isFile()) {
      kind = 'file';
    } else {
      throw localUsage('local_invalid_type', 'local target must be a regular file or directory');
    }
    if (input.overwrite !== true) {
      throw localUsage('target_exists', 'local target already exists (overwrite is false)');
    }
    if (kind === 'file') assertFileSize(stat.size, input.limits, 'local target');
  }

  const roots = await resolveRoots(input.roots);
  let realParent: string;
  try {
    realParent = await fs.realpath(parent);
  } catch (err) {
    throw lstatError(err, 'local_parent_missing', 'local target parent');
  }
  assertContainedInAny(roots, realParent);

  let realPath: string | undefined;
  if (stat !== undefined) {
    try {
      realPath = await fs.realpath(abs);
    } catch (err) {
      throw lstatError(err, 'local_io_error', 'local target');
    }
    assertContainedInAny(roots, realPath);
  }

  return {
    path: abs,
    exists: stat !== undefined,
    ...(realPath !== undefined ? { realPath } : {}),
    ...(kind !== undefined ? { kind } : {}),
    ...(stat !== undefined ? { size: stat.size, mode: stat.mode & 0o777 } : {}),
  };
}

/** 同目录临时路径：`.remote-mcp-<kind>-<16 hex>`。 */
export function newLocalTempPath(dir: string, kind: string): string {
  if (!/^[a-z0-9][a-z0-9-]{0,31}$/.test(kind)) {
    throw localUsage('local_path_invalid', 'temporary file kind must be lowercase [a-z0-9-]');
  }
  return path.join(path.resolve(dir), `.remote-mcp-${kind}-${randomBytes(8).toString('hex')}`);
}

export interface BuildLocalManifestInput {
  root: string;
  limits: FileLimits;
  /** 是否为普通文件计算 sha256（默认 true）。 */
  hash?: boolean;
  home?: string;
}

async function sha256File(file: string): Promise<string> {
  const { createHash } = await import('node:crypto');
  const { createReadStream } = await import('node:fs');
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

/**
 * 构建本地目录清单：不跟随 symlink、mode 掩码 0o777、执行 maxFiles/maxDepth/maxTotalBytes。
 * 根为目录时只包含其子项；根为文件时返回单个 path="." 的条目。
 */
export async function buildLocalManifest(input: BuildLocalManifestInput): Promise<ManifestEntry[]> {
  const home = input.home ?? os.homedir();
  const abs = preparePath(input.root, home);
  const hashFiles = input.hash !== false;

  let rootStat: Stats;
  try {
    rootStat = await fs.lstat(abs);
  } catch (err) {
    throw lstatError(err, 'local_source_not_found', 'local manifest root');
  }
  if (rootStat.isSymbolicLink()) {
    throw localUsage('local_symlink', 'local manifest root must not be a symbolic link');
  }

  if (rootStat.isFile()) {
    assertFileSize(rootStat.size, input.limits, 'local manifest root');
    const entry: ManifestEntry = {
      path: '.',
      type: 'file',
      size: rootStat.size,
      mode: rootStat.mode & 0o777,
    };
    if (hashFiles) entry.sha256 = await sha256File(abs);
    return [entry];
  }
  if (!rootStat.isDirectory()) {
    throw localUsage('local_invalid_type', 'local manifest root must be a file or directory');
  }

  const entries: ManifestEntry[] = [];
  let totalBytes = 0;

  const walk = async (dirAbs: string, relDir: string, depth: number): Promise<void> => {
    const dirents = await fs.readdir(dirAbs, { withFileTypes: true });
    dirents.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const dirent of dirents) {
      assertDepth(depth, input.limits, dirent.name);
      const childRel = relDir === '' ? dirent.name : `${relDir}/${dirent.name}`;
      const childAbs = path.join(dirAbs, dirent.name);
      const stat = await fs.lstat(childAbs);

      if (stat.isSymbolicLink()) {
        entries.push({
          path: childRel,
          type: 'symlink',
          size: 0,
          mode: stat.mode & 0o777,
          linkTarget: await fs.readlink(childAbs),
        });
      } else if (stat.isDirectory()) {
        entries.push({
          path: childRel,
          type: 'dir',
          size: 0,
          mode: stat.mode & 0o777,
        });
        assertFileCount(entries.length, input.limits, 'local manifest');
        await walk(childAbs, childRel, depth + 1);
        continue;
      } else if (stat.isFile()) {
        assertFileSize(stat.size, input.limits, childRel);
        totalBytes += stat.size;
        assertTotalBytes(totalBytes, input.limits, 'local manifest');
        const entry: ManifestEntry = {
          path: childRel,
          type: 'file',
          size: stat.size,
          mode: stat.mode & 0o777,
        };
        if (hashFiles) entry.sha256 = await sha256File(childAbs);
        entries.push(entry);
      } else {
        throw localUsage(
          'local_invalid_type',
          `local manifest entry ${JSON.stringify(childRel)} is not a regular file, directory or symlink`,
        );
      }
      assertFileCount(entries.length, input.limits, 'local manifest');
    }
  };

  await walk(abs, '', 1);
  return sortManifestEntries(entries);
}
