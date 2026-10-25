import type { ResolvedTarget } from '../pipeline/target.js';
import { runSshCommand } from '../pipeline/run-command.js';
import { buildSftpArgv, type SshMode } from '../policy/argv.js';
import { buildChildEnv } from '../ssh/env.js';
import { runSftp } from '../ssh/runner.js';
import type { Logger, RunResult } from '../types.js';
import type { FileLimits } from './file-policy.js';

/** 控制通道单条命令的执行选项（timeout 已按 deadline 裁剪）。 */
export interface TransferControlRunOptions {
  timeoutMs: number;
  maxOutputBytes: number;
}

/** 控制通道的执行事实；stdout 已还原为文本（base64 输出会先解码）。 */
export interface TransferControlResult {
  exitCode: number | null;
  stdout: string;
  timedOut: boolean;
  durationMs: number;
}

/**
 * 可选的持久控制通道：一条常驻 SSH 会话承载多条远端控制命令
 * （probe / hash / mkdir / mv / rm）。数据面（sftp 与 tar 流）不经过它，
 * 仍各自使用一次性连接。
 */
export interface TransferControl {
  run(command: string, opts: TransferControlRunOptions): Promise<TransferControlResult>;
}

/**
 * 传输操作的共享依赖（不依赖 ToolContext；由 tools 层组装）。
 * deadlineMs 是本工具调用的绝对截止时间（epoch ms）。
 */
export interface TransferDeps {
  target: ResolvedTarget;
  /** 校验 host key 用的 known_hosts 路径。 */
  knownHostsFile: string;
  log: Logger;
  limits: FileLimits;
  deadlineMs: number;
  /** 远端 home（已解析）；未解析时由 probe 按需获取。 */
  home?: string;
  /**
   * 可选的持久控制通道。存在时 `runRemoteCommand` 走它；不存在时保持
   * 每次调用一条新 SSH 连接的旧路径。
   */
  control?: TransferControl;
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
 * 控制通道失败时的 RunResult：按 ssh 传输失败（退出码 255）上报，
 * 让调用方走既有的 ssh_transport_failure 分类与失败路径。
 */
function controlFailureResult(
  command: string,
  startedAt: number,
  err: unknown,
): RunResult {
  const message = err instanceof Error ? err.message : String(err);
  return {
    argv: [],
    displayCommand: command,
    exitCode: 255,
    signal: null,
    stdout: '',
    // 本地控制通道错误放进 stderr，分类器会以脱敏后的尾部展示。
    stderr: message,
    stdoutBytes: 0,
    stderrBytes: Buffer.byteLength(message, 'utf8'),
    stdoutTruncated: false,
    stderrTruncated: false,
    timedOut: false,
    durationMs: Math.max(0, Date.now() - startedAt),
  };
}

/**
 * 执行一条远端命令：timeout 取 min(requested, remainingMs(deps))。
 * 只返回运行事实，不做退出码分类。
 *
 * 有 `deps.control` 时走常驻会话；带 stdinData/stdinFile/stdoutFile 的调用
 * （tar 流、数据面）仍走一次性 `runSshCommand`，因为控制通道只承载文本输出。
 */
export async function runRemoteCommand(
  deps: TransferDeps,
  command: string,
  opts: RunRemoteOptions = {},
): Promise<RunResult> {
  const requested = opts.timeoutMs ?? deps.target.host.timeouts.commandMs;
  const timeoutMs = Math.min(requested, remainingMs(deps));
  const maxOutputBytes =
    opts.maxOutputBytes ?? deps.target.config.defaults.maxOutputBytes;
  const control = deps.control;
  const usesStreams =
    opts.stdinData !== undefined ||
    opts.stdinFile !== undefined ||
    opts.stdoutFile !== undefined;

  if (control !== undefined && !usesStreams) {
    const startedAt = Date.now();
    try {
      const result = await control.run(command, { timeoutMs, maxOutputBytes });
      return {
        argv: [],
        displayCommand: command,
        exitCode: result.exitCode,
        signal: null,
        stdout: result.stdout,
        stderr: '',
        stdoutBytes: Buffer.byteLength(result.stdout, 'utf8'),
        stderrBytes: 0,
        stdoutTruncated: false,
        stderrTruncated: false,
        timedOut: result.timedOut,
        durationMs: result.durationMs,
      };
    } catch (err) {
      // 会话已关闭/协议错误：按传输失败上报，不在这里回退到新连接，
      // 避免把可能已部分执行的控制命令再执行一次。
      return controlFailureResult(command, startedAt, err);
    }
  }

  return runSshCommand({
    host: deps.target.host,
    knownHostsFile: deps.knownHostsFile,
    remoteCommand: command,
    timeoutMs,
    maxOutputBytes,
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
    knownHostsFile: deps.knownHostsFile,
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
