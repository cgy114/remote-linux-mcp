import type { ResolvedTarget } from '../pipeline/target.js';
import { runSshCommand } from '../pipeline/run-command.js';
import { buildSftpArgv, type SshMode } from '../policy/argv.js';
import { buildChildEnv } from '../ssh/env.js';
import { runSftp } from '../ssh/runner.js';
import type { ToolContext } from '../tools/common.js';
import type { RunResult } from '../types.js';
import type { FileLimits } from './file-policy.js';

/** 传输操作的共享依赖；deadlineMs 是本工具调用的绝对截止时间（epoch ms）。 */
export interface TransferDeps {
  target: ResolvedTarget;
  ctx: ToolContext;
  limits: FileLimits;
  deadlineMs: number;
  /** 远端 home（已解析）；未解析时由 probe 按需获取。 */
  home?: string;
}

/** 距离本工具调用截止时间还剩多少毫秒（不小于 0）。 */
export function remainingMs(deps: TransferDeps): number {
  return Math.max(0, deps.deadlineMs - Date.now());
}

export interface RunRemoteOptions {
  timeoutMs?: number;
  maxOutputBytes?: number;
  stdinData?: string | Buffer;
  stdinFile?: string;
  stdoutFile?: string;
  mode?: SshMode;
  label?: string;
}

/**
 * 执行一条远端命令：timeout 取 min(requested, remainingMs(deps))。
 * 只返回运行事实，不做退出码分类。
 */
export async function runRemoteCommand(
  deps: TransferDeps,
  command: string,
  opts: RunRemoteOptions = {},
): Promise<RunResult> {
  const requested = opts.timeoutMs ?? deps.target.host.timeouts.commandMs;
  const timeoutMs = Math.min(requested, remainingMs(deps));
  return runSshCommand({
    host: deps.target.host,
    knownHostsFile: deps.ctx.paths.knownHostsFile,
    remoteCommand: command,
    timeoutMs,
    maxOutputBytes: opts.maxOutputBytes ?? deps.target.config.defaults.maxOutputBytes,
    mode: opts.mode ?? 'strict',
    ...(opts.stdinData !== undefined ? { stdinData: opts.stdinData } : {}),
    ...(opts.stdinFile !== undefined ? { stdinFile: opts.stdinFile } : {}),
    ...(opts.stdoutFile !== undefined ? { stdoutFile: opts.stdoutFile } : {}),
    label: opts.label ?? `transfer:${deps.target.host.alias}`,
  });
}

export interface RunSftpOptions {
  extra?: readonly string[];
  timeoutMs?: number;
  maxOutputBytes?: number;
  label?: string;
}

/**
 * 以 `sftp -b -` 执行一批步骤；stdin 为以换行分隔的 batch 文本。
 * 步骤文本由 sftp.ts 的构造器生成（已引用/转义，不含裸换行）。
 */
export async function runSftpSteps(
  deps: TransferDeps,
  steps: readonly string[],
  opts: RunSftpOptions = {},
): Promise<RunResult> {
  const { argv } = buildSftpArgv({
    host: deps.target.host,
    knownHostsFile: deps.ctx.paths.knownHostsFile,
    ...(opts.extra !== undefined ? { extra: opts.extra } : {}),
    mode: 'strict',
  });
  const batch = steps.length === 0 ? '' : `${steps.join('\n')}\n`;
  const requested = opts.timeoutMs ?? deps.target.host.timeouts.commandMs;
  const timeoutMs = Math.min(requested, remainingMs(deps));
  return runSftp({
    argv,
    timeoutMs,
    maxOutputBytes: opts.maxOutputBytes ?? deps.target.config.defaults.maxOutputBytes,
    env: buildChildEnv(),
    stdinData: batch,
    label: opts.label ?? `sftp:${deps.target.host.alias}`,
  });
}
