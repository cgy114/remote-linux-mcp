import { statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ConfigError } from '../errors/classes.js';
import type { MCPPaths } from '../types.js';

export const CONFIG_ENV_VAR = 'REMOTE_MCP_CONFIG';

export interface ResolvePathsOptions {
  /** --config 显式参数（最高优先级）。 */
  explicit?: string;
  /** 环境变量表，默认 process.env。 */
  env?: NodeJS.ProcessEnv;
  /** 用户主目录，默认 os.homedir()；测试与 `~` 展开都使用它。 */
  homeDir?: string;
}

/**
 * 解析配置文件位置。优先级：explicit > env.REMOTE_MCP_CONFIG > 默认 `<home>/.remote-mcp/config.yaml`。
 * 默认路径绝不从 cwd 推导。explicit/env 指向已存在的目录时抛 ConfigError('schema')。
 */
export function resolvePaths(opts: ResolvePathsOptions = {}): MCPPaths {
  const env = opts.env ?? process.env;
  const home = opts.homeDir ?? os.homedir();

  let configFile: string;
  let source: MCPPaths['source'];
  if (opts.explicit !== undefined) {
    configFile = resolveUserPath(opts.explicit, home, '--config');
    source = 'flag';
  } else if (env[CONFIG_ENV_VAR]) {
    configFile = resolveUserPath(env[CONFIG_ENV_VAR], home, CONFIG_ENV_VAR);
    source = 'env';
  } else {
    configFile = normalizePath(path.join(home, '.remote-mcp', 'config.yaml'));
    source = 'default';
  }

  const configDir = path.dirname(configFile);
  return {
    configFile,
    configDir,
    knownHostsFile: path.join(configDir, 'known_hosts'),
    trustRegistryFile: path.join(configDir, 'trusted.json'),
    trustLockFile: path.join(configDir, '.trust.lock'),
    source,
  };
}

/** path.resolve 后去掉末尾分隔符（根目录除外）。保留大小写。 */
export function normalizePath(p: string): string {
  const resolved = path.resolve(p);
  const root = path.parse(resolved).root;
  let out = resolved;
  while (out.length > root.length && /[\\/]$/.test(out)) {
    out = out.slice(0, -1);
  }
  return out;
}

/**
 * 展开主目录前缀：`~` 与 `~/...`（Windows 也接受 `~\...`）。
 * `~other` 等不支持的形式抛 ConfigError('schema')；其他路径原样返回。
 */
export function expandHome(p: string, home: string): string {
  if (p === '~') return home;
  if (p.startsWith('~/') || p.startsWith('~\\')) {
    return path.join(home, p.slice(2));
  }
  if (p.startsWith('~')) {
    throw new ConfigError('schema', `unsupported home expansion "${p}" (only "~" and "~/..." are supported)`);
  }
  return p;
}

function resolveUserPath(raw: string, home: string, label: string): string {
  if (raw.trim() === '') {
    throw new ConfigError('schema', `${label}: config path is empty`);
  }
  const abs = normalizePath(expandHome(raw, home));
  if (isExistingDirectory(abs)) {
    throw new ConfigError('schema', `${label}: config path is a directory, expected a file: ${abs}`, {
      path: abs,
    });
  }
  return abs;
}

function isExistingDirectory(file: string): boolean {
  try {
    return statSync(file).isDirectory();
  } catch {
    // 不存在或不可 stat：交给 loadConfig 报告 not_found / io。
    return false;
  }
}
