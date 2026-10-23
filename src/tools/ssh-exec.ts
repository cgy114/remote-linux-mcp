import type { CallToolResult } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { appendAudit, auditFilePath, buildExecAuditRecord } from '../audit/audit.js';
import { UsageError } from '../errors/classes.js';
import { classifyExit, stderrSignatures, toUserError } from '../errors/classify.js';
import { assertAlias } from '../policy/alias.js';
import { buildSshArgv } from '../policy/argv.js';
import {
  buildExecCommand,
  DEFAULT_EXEC_LIMITS,
  MAX_COMMAND_BYTES,
  MAX_STDIN_BYTES,
  validateExecInput as validateRemoteCommandInput,
  type ExecCommandPlan,
  type ExecSizeLimits,
} from '../policy/remote-command.js';
import { assertTarget, effectiveHost, selectJumpSpec } from '../policy/target.js';
import { buildChildEnv } from '../ssh/env.js';
import { getDefaultHostLimiter } from '../ssh/host-limiter.js';
import { runSsh } from '../ssh/runner.js';
import { evaluateTrust } from '../trust/gate.js';
import type { EffectiveHost, Logger, RemoteConfig, RunResult, ToolError } from '../types.js';
import { errorToToolError, textResult, toolErrorResult, type ToolContext } from './common.js';

/** ssh_exec 的输入边界；所有字段在 MCP 层先由 zod 校验。 */
export const sshExecInput = z
  .object({
    host: z.string().min(1).max(64).optional(),
    command: z.string().min(1),
    cwd: z.string().min(1).max(4096).optional(),
    env: z.record(z.string(), z.string()).optional(),
    stdin: z.string().optional(),
    timeout_ms: z.number().int().min(1).max(600_000).optional(),
    max_output_bytes: z.number().int().min(4096).max(8_388_608).optional(),
  })
  .strict();

export type SshExecInput = z.infer<typeof sshExecInput>;

/** ssh_exec 的本地门限；remote 部分交给 policy/remote-command 执行。 */
export interface ExecLimits extends ExecSizeLimits {
  maxCommandBytes: number;
  maxStdinBytes: number;
}

export const EXEC_LIMITS: ExecLimits = {
  maxCommandBytes: MAX_COMMAND_BYTES,
  maxStdinBytes: MAX_STDIN_BYTES,
  ...DEFAULT_EXEC_LIMITS,
};

export interface ExecTarget {
  config: RemoteConfig;
  host: EffectiveHost;
  destination: string;
}

/**
 * 解析目标主机：host > defaults.default_host。缺失时抛 missing_host，
 * 其余用 policy 层校验（alias、jump 链、目标三元组）。
 */
export async function resolveExecTarget(
  input: Pick<SshExecInput, 'host'>,
  ctx: ToolContext,
): Promise<ExecTarget> {
  const config = await ctx.getConfig();
  const alias = input.host ?? config.defaults.defaultHost;
  if (alias === undefined || alias === '') {
    throw new UsageError('missing_host', { code: 'missing_host' });
  }
  const checked = assertAlias(alias);
  const host = effectiveHost(config, checked);
  const jumps = selectJumpSpec(host.proxyJump);
  assertTarget({ user: host.user, host: host.host, port: host.port, jumps });
  return { config, host, destination: `${host.user}@${host.host}:${host.port}` };
}

/**
 * 前置输入校验。命令/环境/stdin/cwd 的规则集中在 policy/remote-command。
 * 未提供 cwd 时不做 cwd 校验；真实 cwd（input.cwd ?? host.cwd）由 buildExecCommand 校验。
 */
export function validateExecInput(input: SshExecInput): void {
  validateRemoteCommandInput({
    command: input.command,
    ...(input.cwd !== undefined ? { cwd: input.cwd } : {}),
    ...(input.env !== undefined ? { env: input.env } : {}),
    ...(input.stdin !== undefined ? { stdin: input.stdin } : {}),
  });
}

/**
 * ssh_exec：严格按 校验 -> 解析目标 -> 信任门禁 -> 构建 -> 限流 -> 执行 -> 审计 -> 格式化。
 * 任何异常都在本层转成 isError 结果，绝不向传输层抛出。
 */
export async function sshExec(input: SshExecInput, ctx: ToolContext): Promise<CallToolResult> {
  let alias: string | undefined;
  try {
    validateExecInput(input);

    const { host, destination } = await resolveExecTarget(input, ctx);
    alias = host.alias;

    // 信任门禁必须在任何 spawn 之前；失败即返回 HostKey 类错误。
    const trust = await evaluateTrust({ alias: host.alias, host, paths: ctx.paths, log: ctx.log });
    if (!trust.ok) {
      const fact = trust.fact;
      const err = toUserError(
        {
          phase: 'trust',
          ...(fact.reason !== undefined ? { reason: fact.reason } : {}),
          ...(fact.stderr !== undefined ? { stderr: fact.stderr } : {}),
        },
        ctx.log,
      );
      return toolErrorResult(err, alias);
    }

    const cwd = input.cwd ?? host.cwd;
    const plan = buildExecCommand({
      command: input.command,
      cwd,
      env: input.env ?? {},
      ...(input.stdin !== undefined ? { stdin: input.stdin } : {}),
      limits: {
        maxRemoteUtf16: EXEC_LIMITS.maxRemoteUtf16,
        maxRemoteUtf8: EXEC_LIMITS.maxRemoteUtf8,
      },
    });

    const timeoutMs = input.timeout_ms ?? host.timeouts.commandMs;
    const maxOutputBytes = input.max_output_bytes ?? host.maxOutputBytes;

    const permit = await getDefaultHostLimiter().acquire(destination);
    try {
      const { argv } = buildSshArgv({
        host,
        knownHostsFile: ctx.paths.knownHostsFile,
        remoteCommand: plan.remoteCommand,
        mode: 'strict',
      });
      const run = await runSsh({
        argv,
        timeoutMs,
        maxOutputBytes,
        env: buildChildEnv(),
        ...(input.stdin !== undefined ? { stdinData: input.stdin } : {}),
        label: `ssh_exec:${alias}`,
      });

      const failure = execFailure(run, ctx.log);

      // 审计只记录退出事实与命令摘要；appendAudit 永不 reject，失败不影响结果。
      await appendAudit(
        buildExecAuditRecord({
          alias: host.alias,
          destination,
          commandSha256: plan.commandSha256,
          commandBytes: plan.commandBytes,
          cwd: plan.cwd,
          envKeys: plan.envKeys,
          stdinBytes: plan.stdinBytes,
          run,
          queueMs: permit.queueMs,
          ...(failure !== undefined
            ? { failure: { code: failure.code, kind: failure.kind, message: failure.message } }
            : {}),
        }),
        { file: auditFilePath(ctx.paths.configDir), log: ctx.log },
      );

      return formatExecResult({
        alias: host.alias,
        host,
        destination,
        plan,
        run,
        queueMs: permit.queueMs,
        ...(failure !== undefined ? { failure } : {}),
      });
    } finally {
      permit.release();
    }
  } catch (e) {
    return toolErrorResult(errorToToolError(e, ctx.log), alias);
  }
}

/**
 * 退出事实 -> ToolError。
 * spawn 失败 = Internal；超时 = Timeout；255 走 stderr 特征分类，无法识别时
 * classify/toUserError 统一归为 ssh_transport_failure；0–254 是远端命令结果，不是错误。
 */
export function execFailure(run: RunResult, log?: Logger): ToolError | undefined {
  if (run.spawnError !== undefined) {
    return toUserError({ phase: 'exec', spawnError: run.spawnError }, log);
  }
  if (run.timedOut) {
    return toUserError({ phase: 'exec', timedOut: true }, log);
  }
  if (typeof run.exitCode === 'number' && run.exitCode >= 0 && run.exitCode <= 254) {
    return undefined;
  }
  // 255 / null 退出码 / 被信号终止：交给统一分类；255 无特征时由 toUserError 覆盖为传输层失败。
  return toUserError(
    {
      phase: 'exec',
      ...classifyExit(run),
      stderr: run.stderr,
      signatures: stderrSignatures(run.stderr),
    },
    log,
  );
}

export interface FormatExecResultInput {
  alias: string;
  host: EffectiveHost;
  destination: string;
  plan: ExecCommandPlan;
  run: RunResult;
  queueMs: number;
  failure?: ToolError;
}

/** 去掉恰好一个行尾换行，避免文本分段出现多余空行。 */
function stripTrailingNewline(text: string): string {
  if (text.endsWith('\r\n')) return text.slice(0, -2);
  if (text.endsWith('\n')) return text.slice(0, -1);
  return text;
}

/**
 * 结果格式化。文本首行为退出摘要，stdout/stderr 分段（空则省略）。
 * structuredContent 只含输出摘要，绝不返回 argv/command/env/stdin。
 */
export function formatExecResult(input: FormatExecResultInput): CallToolResult {
  const { run, failure } = input;
  const meta = [`${run.durationMs}ms`];
  if (input.queueMs > 0) meta.push(`queued ${input.queueMs}ms`);
  if (run.timedOut) meta.push('timed out');

  const lines: string[] = [
    `${input.alias}: exit=${run.exitCode === null ? 'null' : String(run.exitCode)} (${meta.join(', ')})`,
  ];

  if (failure !== undefined) {
    lines.push(`error: [${failure.kind}] ${failure.code}: ${failure.message}`);
  }
  if (run.stdout.length > 0) {
    lines.push('stdout:', stripTrailingNewline(run.stdout));
    if (run.stdoutTruncated) lines.push('[stdout truncated]');
  }
  if (run.stderr.length > 0) {
    lines.push('stderr:', stripTrailingNewline(run.stderr));
    if (run.stderrTruncated) lines.push('[stderr truncated]');
  }

  const structured: Record<string, unknown> = {
    host: input.alias,
    destination: input.destination,
    exit_code: run.exitCode,
    stdout: run.stdout,
    stderr: run.stderr,
    truncated: run.stdoutTruncated || run.stderrTruncated,
    timed_out: run.timedOut,
    duration_ms: run.durationMs,
    stdout_bytes: run.stdoutBytes,
    stderr_bytes: run.stderrBytes,
    stdout_truncated: run.stdoutTruncated,
    stderr_truncated: run.stderrTruncated,
    queue_ms: input.queueMs,
  };

  if (failure !== undefined) {
    structured['error'] = {
      kind: failure.kind,
      code: failure.code,
      message: failure.message,
      hint: failure.hint,
    };
    return {
      content: [{ type: 'text', text: lines.join('\n') }],
      structuredContent: structured,
      isError: true,
    };
  }

  const result = textResult(lines.join('\n'), structured);
  result.isError = false;
  return result;
}
