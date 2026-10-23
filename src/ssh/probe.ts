import { randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { classifyExit, stderrSignatures } from '../errors/classify.js';
import { buildSshArgv, buildSshGArgv } from '../policy/argv.js';
import type {
  CheckFacts,
  EffectiveHost,
  ErrorFacts,
  KnownHostEntry,
  Logger,
  MCPPaths,
  RunResult,
} from '../types.js';
import { resolveSshBinary } from './binary.js';
import { buildChildEnv } from './env.js';
import { hostKeyUnknownSignature } from './preflight.js';
import { spawnCapture } from './runner.js';

const PROBE_MAX_OUTPUT_BYTES = 64 * 1024;
const SSH_G_TIMEOUT_MS = 10_000;

/** 检查命令的标记前缀；实际标记为 前缀 + 随机后缀。 */
export const CHECK_MARKER_BEGIN_PREFIX = 'REMOTE_MCP_CHECK_BEGIN_';
export const CHECK_MARKER_END_PREFIX = 'REMOTE_MCP_CHECK_END_';

export type ProbeHostKeyResult =
  | { ok: true; entries: KnownHostEntry[]; tempFile: string }
  | { ok: false; fact: ErrorFacts };

export type VerifyResult = { ok: true } | { ok: false; fact: ErrorFacts };

// ---------- 内部辅助 ----------

function internalError(message: string, code: string): Error {
  const err = new Error(`[Internal] ${message}`) as Error & { code?: string; kind?: string };
  err.code = code;
  err.kind = 'Internal';
  return err;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** 在 argv 构造失败或二进制缺失时返回一个合成的 RunResult（不抛）。 */
function syntheticFailure(code: string, message: string): RunResult {
  return {
    argv: [],
    displayCommand: '',
    exitCode: null,
    signal: null,
    stdout: '',
    stderr: '',
    stdoutTruncated: false,
    stderrTruncated: false,
    timedOut: false,
    durationMs: 0,
    spawnError: { code, message },
  };
}

/**
 * 以指定 ssh 路径（默认解析系统 ssh）运行 argv。不抛：找不到二进制时返回 spawnError。
 * 与 runSsh 等价，但允许注入 sshPath 并接受外部 env；不修改 runner.ts。
 */
async function runSshWithPath(input: {
  sshPath?: string;
  argv: readonly string[];
  env: NodeJS.ProcessEnv;
  timeoutMs: number;
  maxOutputBytes: number;
}): Promise<RunResult> {
  let file = input.sshPath;
  if (file === undefined) {
    try {
      file = (await resolveSshBinary()).path;
    } catch (err) {
      return syntheticFailure('binary_missing', errorMessage(err));
    }
  }
  return spawnCapture({
    file,
    argv: input.argv,
    env: input.env,
    timeoutMs: input.timeoutMs,
    maxOutputBytes: input.maxOutputBytes,
    stdin: 'ignore',
  });
}

/** 生成一个当前不存在的临时 known_hosts 路径。 */
async function allocateTempKnownHostsPath(): Promise<string> {
  for (let attempt = 0; attempt < 5; attempt++) {
    const candidate = path.join(
      os.tmpdir(),
      `remote-mcp-known-hosts-${process.pid}-${randomBytes(8).toString('hex')}`,
    );
    try {
      await fs.lstat(candidate);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return candidate;
      throw err;
    }
  }
  throw internalError('cannot allocate a unique temp known_hosts path', 'temp_path_exhausted');
}

async function readTextIfExists(file: string): Promise<string | undefined> {
  try {
    return await fs.readFile(file, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw err;
  }
}

async function removeQuietly(file: string): Promise<void> {
  try {
    await fs.rm(file, { force: true });
  } catch {
    // 删除失败不影响结果
  }
}

/** 单引号安全转义，用于 POSIX sh 单词。 */
function shSingleQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

// ---------- known_hosts 解析 ----------

/**
 * 最小解析 known_hosts 文本。跳过空行、`#` 与 `@` 开头的行；
 * 每条为 `<hosts> <algo> <base64>`，hosts 按逗号拆分（known_hosts 的格式约定）。
 */
export function parseKnownHosts(text: string): KnownHostEntry[] {
  const entries: KnownHostEntry[] = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((rawLine, index) => {
    const trimmed = rawLine.trim();
    if (trimmed === '' || trimmed.startsWith('#') || trimmed.startsWith('@')) return;
    const parts = trimmed.split(/\s+/);
    const hostsField = parts[0];
    const algorithm = parts[1];
    const keyBlob = parts[2];
    if (hostsField === undefined || algorithm === undefined || keyBlob === undefined) return;
    entries.push({
      marker: null,
      hosts: hostsField.split(',').filter((h) => h.length > 0),
      algorithm,
      keyBlob,
      raw: rawLine,
      line: index + 1,
    });
  });
  return entries;
}

// ---------- 主机密钥探测 ----------

/**
 * 用 accept-new 连接一次，让 ssh 把远端主机密钥写入临时 known_hosts，再读回解析。
 * 不关心退出码（认证失败前主机密钥已写入）。临时文件在 finally 中删除。不抛。
 */
export async function probeHostKey(input: {
  host: EffectiveHost;
  paths: MCPPaths;
  timeoutMs: number;
  log: Logger;
  sshPath?: string;
}): Promise<ProbeHostKeyResult> {
  const { host, timeoutMs, log, sshPath } = input;
  let tempFile: string | undefined;
  try {
    tempFile = await allocateTempKnownHostsPath();
    const { argv } = buildSshArgv({
      host,
      knownHostsFile: tempFile,
      mode: 'accept-new',
      remoteCommand: 'true',
    });
    const run = await runSshWithPath({
      sshPath,
      argv,
      env: buildChildEnv(),
      timeoutMs,
      maxOutputBytes: PROBE_MAX_OUTPUT_BYTES,
    });
    const text = await readTextIfExists(tempFile);
    const hasText = text !== undefined && text.trim() !== '';

    if ((run.spawnError !== undefined || run.timedOut) && !hasText) {
      log.debug('host key probe failed before producing known_hosts');
      return {
        ok: false,
        fact: { phase: 'probe', stderr: run.stderr, ...classifyExit(run) },
      };
    }

    const entries = parseKnownHosts(text ?? '');
    if (entries.length !== 1) {
      log.debug(`host key probe produced ${entries.length} entries`);
      return {
        ok: false,
        fact: {
          phase: 'probe',
          signatures: hostKeyUnknownSignature(),
          reason: 'probe_ambiguous',
        },
      };
    }
    return { ok: true, entries, tempFile };
  } catch (err) {
    log.warn(`host key probe internal error: ${errorMessage(err)}`);
    return {
      ok: false,
      fact: { phase: 'probe', reason: 'internal', stderr: errorMessage(err) },
    };
  } finally {
    if (tempFile !== undefined) await removeQuietly(tempFile);
  }
}

// ---------- 严格连接校验 ----------

/** 以 strict 模式连接并执行 `true`，验证已固定的主机密钥与认证。不抛。 */
export async function verifyTrustedConnection(input: {
  host: EffectiveHost;
  paths: MCPPaths;
  log: Logger;
  sshPath?: string;
}): Promise<VerifyResult> {
  const { host, paths, log, sshPath } = input;
  try {
    const { argv } = buildSshArgv({
      host,
      knownHostsFile: paths.knownHostsFile,
      mode: 'strict',
      remoteCommand: 'true',
    });
    const run = await runSshWithPath({
      sshPath,
      argv,
      env: buildChildEnv(),
      timeoutMs: host.timeouts.checkMs,
      maxOutputBytes: PROBE_MAX_OUTPUT_BYTES,
    });
    if (run.exitCode === 0 && !run.timedOut && run.spawnError === undefined) {
      return { ok: true };
    }
    log.debug(`strict verify failed with exit ${String(run.exitCode)}`);
    return {
      ok: false,
      fact: {
        phase: 'verify',
        ...classifyExit(run),
        stderr: run.stderr,
        signatures: stderrSignatures(run.stderr),
      },
    };
  } catch (err) {
    return {
      ok: false,
      fact: { phase: 'verify', reason: 'internal', stderr: errorMessage(err) },
    };
  }
}

// ---------- 远端检查命令 ----------

/**
 * 生成单条 POSIX sh 命令：输出开始标记、uname、sshd 版本（按顺序取第一个成功的）、结束标记。
 * 标记做单引号转义；除换行外不插入任何用户输入。
 */
export function buildCheckCommand(input: { markerBegin: string; markerEnd: string }): string {
  for (const m of [input.markerBegin, input.markerEnd]) {
    if (/[\r\n\0]/.test(m)) {
      throw new Error('check markers must not contain newline or NUL');
    }
  }
  const begin = shSingleQuote(input.markerBegin);
  const end = shSingleQuote(input.markerEnd);
  const versionChain =
    'v=$(sshd -V 2>&1) || v=$(/usr/sbin/sshd -V 2>&1) || ' +
    "v=$(dpkg-query -W -f='${Version}' openssh-server 2>/dev/null) || " +
    'v=$(ssh -V 2>&1)';
  return [
    `printf '%s\\n' ${begin}`,
    'uname -srm',
    versionChain,
    `printf '%s\\n' "$v"`,
    `printf '%s\\n' ${end}`,
  ].join('; ');
}

/**
 * 解析检查命令输出。标记按固定前缀定位，允许前后有其他输出。
 * 第一行非空为 uname；其余内容中匹配 OpenSSH 版本或 dpkg 版本号。
 * 找不到标记时抛 Internal（code='invalid_output'）。
 */
export function parseCheckOutput(stdout: string): CheckFacts {
  const lines = stdout.split(/\r?\n/);
  const beginIdx = lines.findIndex((l) => l.includes(CHECK_MARKER_BEGIN_PREFIX));
  if (beginIdx === -1) {
    throw internalError('check output missing begin marker', 'invalid_output');
  }
  const endRel = lines.slice(beginIdx + 1).findIndex((l) => l.includes(CHECK_MARKER_END_PREFIX));
  if (endRel === -1) {
    throw internalError('check output missing end marker', 'invalid_output');
  }
  const body = lines.slice(beginIdx + 1, beginIdx + 1 + endRel);

  const facts: CheckFacts = {};
  const unameIdx = body.findIndex((l) => l.trim() !== '');
  if (unameIdx === -1) return facts;
  facts.uname = body[unameIdx]!.trim();

  const rest = body.slice(unameIdx + 1).join('\n');
  const openssh = /OpenSSH[_\s].*?(\d+\.\d+)/i.exec(rest);
  if (openssh !== null && openssh[1] !== undefined) {
    facts.sshdVersion = openssh[1];
  } else {
    const dpkg = /^\s*(?:\d+:)?(\d+\.\d+)/m.exec(rest);
    if (dpkg !== null && dpkg[1] !== undefined) facts.sshdVersion = dpkg[1];
  }
  return facts;
}

/** 以 strict 模式运行检查命令。不抛：失败通过 RunResult.spawnError / exitCode 表达。 */
export async function runHostCheckProbe(input: {
  host: EffectiveHost;
  paths: MCPPaths;
  timeoutMs: number;
  maxOutputBytes: number;
  log: Logger;
  sshPath?: string;
}): Promise<RunResult> {
  const { host, paths, timeoutMs, maxOutputBytes, log, sshPath } = input;
  try {
    const nonce = randomBytes(8).toString('hex');
    const command = buildCheckCommand({
      markerBegin: `${CHECK_MARKER_BEGIN_PREFIX}${nonce}`,
      markerEnd: `${CHECK_MARKER_END_PREFIX}${nonce}`,
    });
    const { argv } = buildSshArgv({
      host,
      knownHostsFile: paths.knownHostsFile,
      mode: 'strict',
      remoteCommand: command,
    });
    return await runSshWithPath({
      sshPath,
      argv,
      env: buildChildEnv(),
      timeoutMs,
      maxOutputBytes,
    });
  } catch (err) {
    log.warn(`host check probe could not start: ${errorMessage(err)}`);
    return syntheticFailure('invalid_argv', errorMessage(err));
  }
}

// ---------- ssh -G ----------

/** 解析 `ssh -G` 输出：每行 `key value`，key 小写，同名多次出现合并为数组。 */
export function parseSshG(stdout: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const line of stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === '') continue;
    const m = /^(\S+)(?:\s+(.*))?$/.exec(trimmed);
    if (m === null || m[1] === undefined) continue;
    const key = m[1].toLowerCase();
    const value = (m[2] ?? '').trim();
    (out[key] ??= []).push(value);
  }
  return out;
}

/** 运行 `ssh -G` 解析有效客户端配置。非零退出、超时或 spawn 失败抛 Internal（ssh_g_failed）。 */
export async function runSshG(input: {
  host: EffectiveHost;
  env: NodeJS.ProcessEnv;
  timeoutMs?: number;
  sshPath?: string;
}): Promise<Record<string, string[]>> {
  const run = await runSshWithPath({
    sshPath: input.sshPath,
    argv: buildSshGArgv(input.host),
    env: input.env,
    timeoutMs: input.timeoutMs ?? SSH_G_TIMEOUT_MS,
    maxOutputBytes: PROBE_MAX_OUTPUT_BYTES,
  });
  if (run.spawnError !== undefined || run.timedOut || run.exitCode !== 0) {
    throw internalError(
      `ssh -G failed (exit ${String(run.exitCode)}): ${run.stderr.trim() || run.spawnError?.message || ''}`,
      'ssh_g_failed',
    );
  }
  return parseSshG(run.stdout);
}
