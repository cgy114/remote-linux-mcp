#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { loadConfig } from './config/load.js';
import { resolvePaths } from './config/paths.js';
import { EXIT } from './constants.js';
import {
  CredentialError,
  getCredentialProvider,
  MAX_CREDENTIAL_BYTES,
  type WritableCredentialProvider,
} from './credentials/index.js';
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
  | {
      kind: 'credential';
      action: 'set' | 'status' | 'delete';
      ref: string;
      stdin: boolean;
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
      stdin: { type: 'boolean' },
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
    if (values.stdin === true) {
      throw new UsageError('--stdin applies only to credential set');
    }
    return configPath !== undefined ? { kind: 'serve', configPath } : { kind: 'serve' };
  }

  if (command === 'credential') {
    if (values.rotate === true || fingerprint !== undefined) {
      throw new UsageError('--rotate and --fingerprint apply only to the trust command');
    }
    const action = rest[0];
    if (action !== 'set' && action !== 'status' && action !== 'delete') {
      throw new UsageError(
        'credential requires a subcommand: remote-mcp credential <set|status|delete> <ref>',
      );
    }
    const ref = rest[1];
    if (ref === undefined || ref === '') {
      throw new UsageError(`credential ${action} requires a name: remote-mcp credential ${action} <ref>`);
    }
    if (rest.length > 2) {
      throw new UsageError(`unexpected extra arguments for credential: ${rest.slice(2).join(' ')}`);
    }
    if (values.stdin === true && action !== 'set') {
      throw new UsageError('--stdin applies only to credential set');
    }
    return { kind: 'credential', action, ref, stdin: values.stdin === true };
  }

  if (command === 'trust') {
    if (values.stdin === true) {
      throw new UsageError('--stdin applies only to credential set');
    }
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
  remote-mcp credential set <ref> [--stdin]    把密码存入系统凭据库
  remote-mcp credential status <ref>           查看凭据是否存在（不显示明文）
  remote-mcp credential delete <ref>           删除凭据
  remote-mcp --help | --version

全局选项:
  --config <path>                    指定配置文件（优先于环境变量 REMOTE_MCP_CONFIG）

trust 选项:
  --rotate                           允许替换已变化的已固定主机密钥
  --fingerprint <SHA256:...>         非交互确认：探测到的指纹必须与此完全一致

credential 选项:
  --stdin                            显式从 stdin 读取一行；stdin 是 TTY 时必须指定
                                     不接受 --password（避免密码出现在 argv/进程列表）

示例:
  remote-mcp trust web1                                交互确认（需输入 yes）
  remote-mcp trust web1 --fingerprint SHA256:xxxx      非交互确认（脚本/CI）
  remote-mcp trust web1 --rotate --fingerprint SHA256:xxxx
  printf '%s\\n' "$SUDO_PASSWORD" | remote-mcp credential set sudo.web1
  remote-mcp credential status sudo.web1
  remote-mcp credential delete sudo.web1

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
    case 'credential':
      return runCredentialCommand(cmd, log);
  }
}

export interface CredentialCommandOptions {
  provider?: WritableCredentialProvider;
  stdin?: NodeJS.ReadableStream;
  stdout?: NodeJS.WritableStream;
  stderr?: NodeJS.WritableStream;
}

/**
 * 从流里读一行（到 LF 或 EOF）。不做 trim（密码可含空格），只去掉行尾 CR。
 * 超过 MAX_CREDENTIAL_BYTES 立即失败，避免无限缓冲。
 */
function readSecretLine(stream: NodeJS.ReadableStream): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    let settled = false;

    const cleanup = (): void => {
      stream.removeListener('data', onData);
      stream.removeListener('end', onEnd);
      stream.removeListener('error', onError);
    };
    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      cleanup();
      buffer.fill(0);
      try {
        (stream as { pause?: () => void }).pause?.();
      } catch {
        // 流可能已结束。
      }
      reject(err);
    };
    const finish = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      let line = buffer.toString('utf8');
      buffer.fill(0);
      if (line.endsWith('\r')) line = line.slice(0, -1);
      resolve(line);
    };
    const onData = (chunk: string | Buffer): void => {
      const bytes = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
      const newline = bytes.indexOf(0x0a);
      const take = newline === -1 ? bytes : bytes.subarray(0, newline);
      if (buffer.length + take.length > MAX_CREDENTIAL_BYTES) {
        fail(
          new CredentialError(
            'credential_invalid',
            `credential must be at most ${MAX_CREDENTIAL_BYTES} UTF-8 bytes`,
          ),
        );
        return;
      }
      buffer = Buffer.concat([buffer, take]);
      if (newline !== -1) finish();
    };
    const onEnd = (): void => finish();
    const onError = (err: Error): void => fail(err);

    stream.on('data', onData);
    stream.on('end', onEnd);
    stream.on('error', onError);
  });
}

async function providerHas(provider: WritableCredentialProvider, ref: string): Promise<boolean> {
  if (provider.exists !== undefined) return provider.exists(ref);
  try {
    const secret = await provider.get(ref);
    secret.wipe();
    return true;
  } catch (err) {
    if (err instanceof CredentialError && err.code === 'credential_not_found') return false;
    throw err;
  }
}

function credentialExitCode(err: unknown, stderr: NodeJS.WritableStream, log: Logger): number {
  if (err instanceof UsageError) {
    stderr.write(`remote-mcp: ${err.message}\n`);
    return EXIT.usage;
  }
  if (err instanceof CredentialError) {
    // unavailable/timeout 的底层 message 可能含实现细节；统一用固定文案。
    const message =
      err.code === 'credential_unavailable'
        ? 'credential store is unavailable'
        : err.code === 'credential_timeout'
          ? 'credential lookup timed out'
          : err.message;
    stderr.write(`remote-mcp: ${message}\n`);
    return err.code === 'credential_invalid' ? EXIT.config : EXIT.internal;
  }
  log.error({ err: serializeError(err) }, 'credential command failed');
  stderr.write('remote-mcp: credential command failed\n');
  return EXIT.internal;
}

/**
 * 凭据子命令。stdout 只输出结果词（stored/present/not found/deleted），
 * 绝不输出或回显密码。测试可通过 options 注入 provider 与流。
 */
export async function runCredentialCommand(
  cmd: Extract<CliCommand, { kind: 'credential' }>,
  log: Logger,
  options: CredentialCommandOptions = {},
): Promise<number> {
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const stdin = options.stdin ?? process.stdin;

  let provider: WritableCredentialProvider;
  try {
    provider = options.provider ?? getCredentialProvider();
  } catch (err) {
    return credentialExitCode(err, stderr, log);
  }

  try {
    switch (cmd.action) {
      case 'set': {
        const isTty = (stdin as { isTTY?: boolean }).isTTY === true;
        if (!cmd.stdin && isTty) {
          throw new UsageError(
            'credential set reads the password from stdin; pipe it or pass --stdin',
          );
        }
        const secret = await readSecretLine(stdin);
        if (secret.length === 0) {
          throw new CredentialError('credential_invalid', 'credential must not be empty');
        }
        await provider.set(cmd.ref, secret);
        stdout.write('stored\n');
        return EXIT.ok;
      }
      case 'status': {
        const present = await providerHas(provider, cmd.ref);
        stdout.write(present ? 'present\n' : 'not found\n');
        return EXIT.ok;
      }
      case 'delete': {
        const deleted = await provider.delete(cmd.ref);
        stdout.write(deleted ? 'deleted\n' : 'not found\n');
        return EXIT.ok;
      }
    }
  } catch (err) {
    return credentialExitCode(err, stderr, log);
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
