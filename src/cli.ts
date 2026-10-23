#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { loadConfig } from './config/load.js';
import { resolvePaths } from './config/paths.js';
import { EXIT } from './constants.js';
import { ConfigError, UsageError } from './errors/classes.js';
import { createLogger, serializeError } from './log.js';
import { effectiveHost } from './policy/target.js';
import { serve } from './server.js';
import { runTrustFlow } from './trust/flow.js';
import type { Logger } from './types.js';
import { VERSION } from './version.js';

export type CliCommand =
  | { kind: 'serve'; configPath?: string }
  | {
      kind: 'trust';
      alias: string;
      configPath?: string;
      rotate: boolean;
      fingerprint?: string;
      interactive: boolean;
    }
  | { kind: 'help' }
  | { kind: 'version' };

const FINGERPRINT_PREFIX = 'SHA256:';

/**
 * 解析命令行。无位置参数 -> serve；`trust <alias>` -> trust；--help/-h、--version/-v。
 * 未知选项、缺失参数或未知命令抛 UsageError。
 */
function parseRaw(argv: readonly string[]) {
  return parseArgs({
    args: [...argv],
    allowPositionals: true,
    strict: true,
    options: {
      config: { type: 'string' },
      rotate: { type: 'boolean' },
      fingerprint: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'v' },
    },
  });
}

export function parseCliArgs(argv: readonly string[]): CliCommand {
  let parsed: ReturnType<typeof parseRaw>;
  try {
    parsed = parseRaw(argv);
  } catch (cause) {
    throw new UsageError(cause instanceof Error ? cause.message : String(cause), { cause });
  }

  const { values, positionals } = parsed;
  if (values.help === true) return { kind: 'help' };
  if (values.version === true) return { kind: 'version' };

  const configPath = values.config;
  const fingerprint = values.fingerprint;
  if (fingerprint !== undefined && !fingerprint.startsWith(FINGERPRINT_PREFIX)) {
    throw new UsageError(`--fingerprint must start with "${FINGERPRINT_PREFIX}"`);
  }
  const [command, ...rest] = positionals;

  if (command === undefined) {
    if (values.rotate === true || fingerprint !== undefined) {
      throw new UsageError('--rotate and --fingerprint apply only to the trust command');
    }
    return configPath !== undefined ? { kind: 'serve', configPath } : { kind: 'serve' };
  }

  if (command === 'trust') {
    const alias = rest[0];
    if (alias === undefined || alias === '') {
      throw new UsageError('trust requires an alias: remote-mcp trust <alias>');
    }
    if (rest.length > 1) {
      throw new UsageError(`unexpected extra arguments for trust: ${rest.slice(1).join(' ')}`);
    }
    const cmd: CliCommand = {
      kind: 'trust',
      alias,
      rotate: values.rotate === true,
      interactive: fingerprint === undefined,
    };
    if (configPath !== undefined) cmd.configPath = configPath;
    if (fingerprint !== undefined) cmd.fingerprint = fingerprint;
    return cmd;
  }

  throw new UsageError(`unknown command: ${command}`);
}

const USAGE = `用法:
  remote-mcp [--config <path>]                 以 MCP stdio 模式运行服务器
  remote-mcp trust <alias> [选项]              信任某主机的 SSH 主机密钥
  remote-mcp --help | --version

全局选项:
  --config <path>                    指定配置文件（优先于环境变量 REMOTE_MCP_CONFIG）

trust 选项:
  --rotate                           允许替换已变化的已固定主机密钥
  --fingerprint <SHA256:...>         非交互确认：探测到的指纹必须与此完全一致

示例:
  remote-mcp trust web1                                交互确认（需输入 yes）
  remote-mcp trust web1 --fingerprint SHA256:xxxx      非交互确认（脚本/CI）
  remote-mcp trust web1 --rotate --fingerprint SHA256:xxxx

日志写入 stderr，级别由 REMOTE_MCP_LOG_LEVEL 控制（debug|info|warn|error）。
`;

export function printUsage(stream: NodeJS.WritableStream): void {
  stream.write(USAGE);
}

export async function main(argv: readonly string[]): Promise<number> {
  const log = createLogger();

  let cmd: CliCommand;
  try {
    cmd = parseCliArgs(argv);
  } catch (err) {
    if (err instanceof UsageError) {
      process.stderr.write(`remote-mcp: ${err.message}\n\n`);
      printUsage(process.stderr);
      return EXIT.usage;
    }
    log.error({ err: serializeError(err) }, 'failed to parse arguments');
    return EXIT.internal;
  }

  switch (cmd.kind) {
    case 'help':
      printUsage(process.stdout);
      return EXIT.ok;
    case 'version':
      process.stdout.write(`${VERSION}\n`);
      return EXIT.ok;
    case 'serve':
      return serve({ log, env: process.env, configPath: cmd.configPath });
    case 'trust':
      return runTrustCommand(cmd, log);
  }
}

async function runTrustCommand(
  cmd: Extract<CliCommand, { kind: 'trust' }>,
  log: Logger,
): Promise<number> {
  try {
    const paths = resolvePaths({ explicit: cmd.configPath, env: process.env });
    const config = await loadConfig(paths);
    const host = effectiveHost(config, cmd.alias);
    const outcome = await runTrustFlow({
      host,
      paths,
      rotate: cmd.rotate,
      interactive: cmd.interactive,
      ...(cmd.fingerprint !== undefined ? { assumedFingerprint: cmd.fingerprint } : {}),
      log,
      stdin: process.stdin,
      // 交互提示走 stderr，stdout 只保留最终结果
      stdout: process.stderr,
    });
    if (outcome.ok) {
      process.stdout.write(`${outcome.message}\n`);
      return EXIT.ok;
    }
    process.stderr.write(`${outcome.message}\n`);
    return EXIT.trustFailed;
  } catch (err) {
    if (err instanceof ConfigError || err instanceof UsageError) {
      process.stderr.write(`remote-mcp: ${err.message}\n`);
      return EXIT.config;
    }
    log.error({ err: serializeError(err) }, 'trust command failed');
    return EXIT.internal;
  }
}

function samePath(a: string, b: string): boolean {
  if (process.platform === 'win32') return a.toLowerCase() === b.toLowerCase();
  return a === b;
}

/** 仅当本模块是入口脚本时运行（被 import 时不执行）。 */
function isMainModule(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  const self = fileURLToPath(import.meta.url);
  if (samePath(entry, self)) return true;
  try {
    return samePath(realpathSync(entry), realpathSync(self));
  } catch {
    return pathToFileURL(entry).href === import.meta.url;
  }
}

if (isMainModule()) {
  main(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err: unknown) => {
      process.stderr.write(`remote-mcp: fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
      process.exitCode = EXIT.internal;
    });
}
