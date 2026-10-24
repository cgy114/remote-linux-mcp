#!/usr/bin/env node
/**
 * 只读配置校验器。
 *
 * 复用构建产物（dist/）中的 resolvePaths / loadConfig / loadTrustRegistry，
 * 不重新实现 schema，也不联网、不读凭据、不打印完整配置。
 *
 * 退出码：
 *   0  校验通过
 *   2  用法错误（或 dist 未构建）
 *   3  配置缺失 / IO / 解析 / schema 错误（含信任注册表损坏）
 *   4  --require-trusted 指定的 alias 未受信任
 */

import { access } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const EXIT_OK = 0;
const EXIT_USAGE = 2;
const EXIT_CONFIG = 3;
const EXIT_UNTRUSTED = 4;

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIST_MODULES = [
  ['paths', path.join(REPO_ROOT, 'dist', 'config', 'paths.js')],
  ['load', path.join(REPO_ROOT, 'dist', 'config', 'load.js')],
  ['registry', path.join(REPO_ROOT, 'dist', 'trust', 'registry.js')],
];

const USAGE = `用法: node scripts/check-config.mjs [选项]

选项:
  --config <path>            配置文件路径（默认使用 REMOTE_MCP_CONFIG 或 ~/.remote-mcp/config.yaml）
  --json                     以 JSON 输出结果
  --require-trusted <alias>  要求指定 host alias 已固定在信任注册表中，否则退出码 4
  --quiet                    通过时不输出文本（错误仍然输出）
  -h, --help                 显示本帮助

退出码: 0 通过 / 2 用法或 dist 未构建 / 3 配置错误 / 4 alias 未受信任`;

function usageError(message) {
  const err = new Error(message);
  err.code = 'usage';
  return err;
}

function parseArgs(argv) {
  const opts = { config: undefined, json: false, requireTrusted: undefined, quiet: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--json') {
      opts.json = true;
    } else if (arg === '--quiet') {
      opts.quiet = true;
    } else if (arg === '-h' || arg === '--help') {
      opts.help = true;
    } else if (arg === '--config' || arg === '--require-trusted') {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('--')) {
        throw usageError(`${arg} requires a value`);
      }
      i += 1;
      if (arg === '--config') opts.config = value;
      else opts.requireTrusted = value;
    } else if (arg.startsWith('--config=')) {
      opts.config = requireInlineValue(arg, '--config');
    } else if (arg.startsWith('--require-trusted=')) {
      opts.requireTrusted = requireInlineValue(arg, '--require-trusted');
    } else {
      throw usageError(`unknown argument: ${arg}`);
    }
  }
  return opts;
}

function requireInlineValue(arg, name) {
  const value = arg.slice(name.length + 1);
  if (value.length === 0) throw usageError(`${name} requires a value`);
  return value;
}

async function loadDistModules() {
  for (const [, file] of DIST_MODULES) {
    try {
      await access(file);
    } catch {
      const missing = path.relative(REPO_ROOT, file).replaceAll('\\', '/');
      const err = new Error(`dist 未构建或缺少 ${missing}，请先运行 "npm run build"`);
      err.code = 'dist_missing';
      throw err;
    }
  }
  const [pathsModule, loadModule, registryModule] = await Promise.all([
    import(pathToFileURL(DIST_MODULES[0][1]).href),
    import(pathToFileURL(DIST_MODULES[1][1]).href),
    import(pathToFileURL(DIST_MODULES[2][1]).href),
  ]);
  return {
    resolvePaths: pathsModule.resolvePaths,
    loadConfig: loadModule.loadConfig,
    loadTrustRegistry: registryModule.loadTrustRegistry,
  };
}

function firstHost(config) {
  return Object.keys(config.hosts)[0] ?? null;
}

function summarize(config, paths, registry, requireTrusted) {
  const hosts = Object.keys(config.hosts).length;
  // default_host 未配置时，工具调用必须显式传 host；不要把它伪造成第一台主机。
  const defaultHost = config.defaults.defaultHost ?? null;
  const trustedAlias = requireTrusted ?? defaultHost ?? firstHost(config);
  const present =
    trustedAlias !== null &&
    Object.prototype.hasOwnProperty.call(registry.hosts, trustedAlias);
  return {
    path: paths.configFile,
    hosts,
    defaultHost,
    sudoCredential: config.defaults.sudo.credential ?? null,
    trusted: { alias: trustedAlias, present },
  };
}

function failureJson(summary, code, message) {
  return JSON.stringify({
    ok: false,
    path: summary.path,
    hosts: summary.hosts,
    defaultHost: summary.defaultHost,
    sudoCredential: summary.sudoCredential,
    trusted: summary.trusted,
    error: { code, message },
  });
}

function successJson(summary) {
  return JSON.stringify({
    ok: true,
    path: summary.path,
    hosts: summary.hosts,
    defaultHost: summary.defaultHost,
    sudoCredential: summary.sudoCredential,
    trusted: summary.trusted,
  });
}

function emptySummary() {
  return {
    path: null,
    hosts: null,
    defaultHost: null,
    sudoCredential: null,
    trusted: { alias: null, present: false },
  };
}

/** ConfigError 与运行时其他错误都归一到 {code,message}，不泄露配置内容。 */
function errorInfo(err) {
  if (err !== null && typeof err === 'object' && typeof err.code === 'string') {
    return { code: err.code, message: err instanceof Error ? err.message : String(err) };
  }
  return { code: 'internal', message: err instanceof Error ? err.message : String(err) };
}

async function main(argv) {
  const wantJson = argv.includes('--json');
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    const { code, message } = errorInfo(err);
    return fail(wantJson, emptySummary(), code, message, EXIT_USAGE);
  }

  if (opts.help) {
    process.stdout.write(`${USAGE}\n`);
    return EXIT_OK;
  }

  let modules;
  try {
    modules = await loadDistModules();
  } catch (err) {
    const { code, message } = errorInfo(err);
    return fail(opts.json, emptySummary(), code, message, EXIT_USAGE);
  }

  let paths;
  let config;
  let registry;
  let summary;
  try {
    paths = modules.resolvePaths(
      opts.config !== undefined ? { explicit: opts.config } : {},
    );
    summary = emptySummary();
    summary.path = paths.configFile;
    config = await modules.loadConfig(paths);
    registry = await modules.loadTrustRegistry(paths.trustRegistryFile);
    summary = summarize(config, paths, registry, opts.requireTrusted);
  } catch (err) {
    const { code, message } = errorInfo(err);
    return fail(opts.json, summary, code, message, EXIT_CONFIG);
  }

  if (opts.requireTrusted !== undefined && !summary.trusted.present) {
    const message = `alias "${opts.requireTrusted}" 未受信任（未在 ${paths.trustRegistryFile} 中固定）`;
    return fail(opts.json, summary, 'untrusted', message, EXIT_UNTRUSTED);
  }

  if (opts.json) {
    process.stdout.write(`${successJson(summary)}\n`);
  } else if (!opts.quiet) {
    process.stdout.write(`OK ${summary.path} hosts=${summary.hosts}\n`);
  }
  return EXIT_OK;
}

function fail(json, summary, code, message, exitCode) {
  if (json) {
    process.stdout.write(`${failureJson(summary, code, message)}\n`);
  } else {
    process.stderr.write(`FAIL ${code}: ${message}\n`);
  }
  return exitCode;
}

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err) => {
    process.stderr.write(`FAIL internal: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = EXIT_CONFIG;
  });
