import { buildSshArgv, type SshMode } from '../policy/argv.js';
import { buildChildEnv } from '../ssh/env.js';
import { runSsh } from '../ssh/runner.js';
import type { EffectiveHost, RunResult } from '../types.js';

export interface RunSshCommandInput {
  host: EffectiveHost;
  knownHostsFile: string;
  remoteCommand: string;
  timeoutMs: number;
  maxOutputBytes: number;
  /** 省略时使用 buildChildEnv()。 */
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  stdinData?: string | Buffer;
  stdinFile?: string;
  stdoutFile?: string;
  /** 默认 strict。 */
  mode?: SshMode;
  label: string;
}

/**
 * 构建 ssh argv 并执行一次远端命令。只返回运行事实，不做退出码分类；
 * spawn 失败放在 RunResult.spawnError，不抛。
 */
export async function runSshCommand(input: RunSshCommandInput): Promise<RunResult> {
  const { argv } = buildSshArgv({
    host: input.host,
    knownHostsFile: input.knownHostsFile,
    remoteCommand: input.remoteCommand,
    mode: input.mode ?? 'strict',
  });
  return runSsh({
    argv,
    timeoutMs: input.timeoutMs,
    maxOutputBytes: input.maxOutputBytes,
    env: input.env ?? buildChildEnv(),
    ...(input.cwd !== undefined ? { cwd: input.cwd } : {}),
    ...(input.stdinData !== undefined ? { stdinData: input.stdinData } : {}),
    ...(input.stdinFile !== undefined ? { stdinFile: input.stdinFile } : {}),
    ...(input.stdoutFile !== undefined ? { stdoutFile: input.stdoutFile } : {}),
    label: input.label,
  });
}
