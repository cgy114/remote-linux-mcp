import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parse } from 'yaml';
import { ConfigError } from '../errors/classes.js';
import { serializeError } from '../log.js';
import type { HostConfig, Logger, MCPPaths, RemoteConfig, Security } from '../types.js';
import { expandHome, normalizePath } from './paths.js';
import { configSchema, defaultsFor, type RawConfig } from './schema.js';

/** 每次都重新读盘并校验。缓存由 loadConfigLazy 负责。 */
export async function loadConfig(paths: MCPPaths): Promise<RemoteConfig> {
  const file = paths.configFile;
  const text = await readConfigText(file);
  const doc = parseYaml(text, file);

  const parsed = configSchema.safeParse(doc);
  if (!parsed.success) {
    const summary = parsed.error.issues
      .map((i) => `${i.path.length ? i.path.join('.') : '(root)'}: ${i.message}`)
      .join('; ');
    throw new ConfigError('schema', `invalid config ${file}: ${summary}`, {
      path: file,
      issues: parsed.error.issues,
    });
  }
  const raw = parsed.data;
  const baseDir = paths.configDir;
  const home = os.homedir();

  const resolveLocalRoot = (p: string): string => resolveAgainst(p, baseDir, home);
  const defaults = defaultsFor(raw, { resolveLocalRoot });

  return {
    version: raw.version,
    sourcePath: file,
    baseDir,
    defaults,
    security: buildSecurity(raw, baseDir, home),
    hosts: buildHosts(raw, baseDir, home),
    // 同一对象：修改 defaults.files 与 files 互相可见（P3 只在加载期写入）。
    files: defaults.files,
  };
}

/**
 * 返回记忆化的加载函数：首次调用执行 loadConfig。
 * 成功则缓存结果；失败则缓存同一个错误实例并在后续调用重抛，不再读盘。
 * 失败会通过 log.warn 记录（不写 stdout）。
 */
export function loadConfigLazy(paths: MCPPaths, log: Logger): () => Promise<RemoteConfig> {
  let pending: Promise<RemoteConfig> | undefined;
  return () => {
    if (pending === undefined) {
      pending = loadConfig(paths).catch((err: unknown) => {
        log.warn({ err: serializeError(err), path: paths.configFile }, 'failed to load config');
        throw err;
      });
    }
    return pending;
  };
}

async function readConfigText(file: string): Promise<string> {
  try {
    return await fs.readFile(file, 'utf8');
  } catch (err) {
    if (errCode(err) === 'ENOENT') {
      throw new ConfigError('not_found', `config file not found: ${file}`, { path: file, cause: err });
    }
    throw new ConfigError('io', `cannot read config file: ${file}`, { path: file, cause: err });
  }
}

function parseYaml(text: string, file: string): unknown {
  try {
    return parse(text, { uniqueKeys: true, schema: 'core' });
  } catch (err) {
    if (errCode(err) === 'DUPLICATE_KEY') {
      throw new ConfigError('duplicate_key', `duplicate key in config ${file}: ${errMessage(err)}`, {
        path: file,
        cause: err,
      });
    }
    throw new ConfigError('parse', `YAML syntax error in config ${file}: ${errMessage(err)}`, {
      path: file,
      cause: err,
    });
  }
}

function buildSecurity(raw: RawConfig, baseDir: string, home: string): Security {
  const sec = raw.security;
  const out: Security = { hostKeyPolicy: 'pinned' };
  if (sec?.known_hosts_file !== undefined) {
    out.knownHostsFile = resolveAgainst(sec.known_hosts_file, baseDir, home);
  }
  return out;
}

function buildHosts(raw: RawConfig, baseDir: string, home: string): Record<string, HostConfig> {
  const out: Record<string, HostConfig> = {};
  for (const [alias, h] of Object.entries(raw.hosts)) {
    const host: HostConfig = { host: h.host, user: h.user };
    if (h.port !== undefined) host.port = h.port;
    if (h.identity_file !== undefined) host.identityFile = resolveAgainst(h.identity_file, baseDir, home);
    if (h.proxy_jump !== undefined) host.proxyJump = h.proxy_jump;
    if (h.default_cwd !== undefined) host.defaultCwd = h.default_cwd;
    if (h.description !== undefined) host.description = h.description;
    out[alias] = host;
  }
  return out;
}

/** `~` 展开；相对路径按配置文件所在目录解析为绝对路径。 */
function resolveAgainst(p: string, baseDir: string, home: string): string {
  return normalizePath(path.resolve(baseDir, expandHome(p, home)));
}

function errCode(err: unknown): string | undefined {
  if (typeof err === 'object' && err !== null && 'code' in err) {
    const code = (err as { code?: unknown }).code;
    return typeof code === 'string' ? code : undefined;
  }
  return undefined;
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
