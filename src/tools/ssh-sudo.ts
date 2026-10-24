import type { CallToolResult } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { appendAuditRecord, buildSudoAuditRecord, sha256Hex } from '../audit/audit.js';
import {
  CredentialError,
  getCredentialProvider,
  loadSecret,
  type CredentialProvider,
  type SecretMaterial,
} from '../credentials/index.js';
import { makeToolError } from '../errors/taxonomy.js';
import {
  assertCommandPolicy,
  evaluateCommandPolicy,
  evaluateSudoPolicy,
} from '../policy/command-policy.js';
import {
  DEFAULT_EXEC_LIMITS,
  validateExecInput as validateRemoteCommandInput,
} from '../policy/remote-command.js';
import {
  buildSudoRemoteCommand,
  classifySudoRun,
  composeSudoStdin,
  stripLeadingSudoCommand,
  type SudoRemotePlan,
} from '../policy/sudo.js';
import { runSshOperation } from '../pipeline/operation.js';
import { runSshCommand } from '../pipeline/run-command.js';
import type { RunResult, ToolError } from '../types.js';
import { errorToToolError, toolErrorResult, type ToolAnnotations, type ToolContext } from './common.js';
import { execFailure, formatExecResult, EXEC_LIMITS } from './ssh-exec.js';

/** ssh_sudo 的输入边界：没有 env/stdin/cwd/max_output，密码只来自凭据库。 */
export const sshSudoInput = z
  .object({
    host: z.string().min(1).max(64).optional(),
    command: z.string().min(1),
    timeout_ms: z.number().int().min(1).max(600_000).optional(),
  })
  .strict();

export type SshSudoInput = z.infer<typeof sshSudoInput>;

export const SSH_SUDO_ANNOTATIONS: ToolAnnotations = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: true,
};

const CREDENTIAL_TIMEOUT_MS = 2000;

interface SudoPlan {
  remote: SudoRemotePlan;
  timeoutMs: number;
  maxOutputBytes: number;
  credential?: SecretMaterial;
  /** 凭据缺失/非法/超时/后端不可用：保留为计划事实，execute 不 spawn。 */
  credentialError?: ToolError;
}

interface SudoProduced {
  run?: RunResult;
  credentialError?: ToolError;
}

/** 凭据层错误 -> 工具错误。绝不把底层 message（可能含实现细节）透出。 */
export function sudoCredentialFailure(err: unknown): ToolError {
  const code = err instanceof CredentialError ? err.code : 'credential_unavailable';
  switch (code) {
    case 'credential_not_found':
      return makeToolError('Policy', {
        code: 'sudo_credential_missing',
        message: '配置要求密码 sudo，但凭据库中没有对应条目',
        details: { reason: 'credential_not_found' },
      });
    case 'credential_invalid':
      return makeToolError('Policy', {
        code: 'sudo_credential_invalid',
        message: '凭据内容不合法（为空、超过 1024 字节或包含 NUL/CR/LF）',
        details: { reason: 'credential_invalid' },
      });
    case 'credential_timeout':
      return makeToolError('Timeout', {
        code: 'sudo_credential_timeout',
        message: '读取凭据超时',
        details: { reason: 'credential_timeout' },
      });
    case 'credential_unavailable':
    default:
      return makeToolError('Internal', {
        code: 'sudo_credential_unavailable',
        message: '凭据后端不可用（系统凭据库无法访问）',
        details: { reason: 'credential_unavailable' },
      });
  }
}

function credentialProviderOf(ctx: ToolContext): CredentialProvider {
  return ctx.credentialProvider ?? getCredentialProvider();
}

/**
 * 分类 sudo 失败：先看 sudo 特征（密码错误/TTY/无密码），再看通用 exec 分类。
 * 非零退出码 1–254 且无 sudo 特征时视为远端命令结果，不是错误。
 */
export function classifySudoFailure(produced: SudoProduced, log?: ToolContext['log']): ToolError | undefined {
  if (produced.credentialError !== undefined) return produced.credentialError;
  const run = produced.run;
  if (run === undefined) {
    return makeToolError('Internal', {
      code: 'internal_error',
      message: 'sudo 执行没有产生运行事实',
    });
  }
  if (typeof run.exitCode === 'number' && run.exitCode !== 0) {
    const sudoFailure = classifySudoRun(run);
    if (sudoFailure !== undefined) return sudoFailure;
  }
  return execFailure(run, log);
}

function sudoErrorResult(err: ToolError, alias: string, sudoMode: string): CallToolResult {
  const result = toolErrorResult(err, alias, 'ssh_sudo');
  const structured = result.structuredContent as Record<string, unknown>;
  structured['sudo_mode'] = sudoMode;
  return result;
}

/**
 * ssh_sudo：在已信任主机上通过 sudo 执行命令。
 *
 * 顺序：命令策略 -> sudo 策略 -> 构建包装命令 -> 读取凭据（password 模式）
 * -> 租约 -> 执行。策略拒绝发生在 spawn 之前；密码只通过 stdin 传给 sudo，
 * 不进入 argv/env/审计/日志/结构化结果。
 */
export async function sshSudo(input: SshSudoInput, ctx: ToolContext): Promise<CallToolResult> {
  let pendingCredential: SecretMaterial | undefined;
  let observedMode: 'off' | 'passwordless' | 'password' = 'off';

  try {
    return await runSshOperation<SudoPlan, SudoProduced>({
      input,
      ctx,
      toolName: 'ssh_sudo',
      prepare: async (target) => {
        const policy = target.config.security.commandPolicy;
        // ssh_sudo 本身已经提权；允许用户传入 `sudo ...` 并剥掉冗余前缀，
        // 否则 hard-sudo 会误拒，远端也会形成嵌套 sudo。
        const command = stripLeadingSudoCommand(input.command);

        assertCommandPolicy(
          evaluateCommandPolicy({
            command,
            policy,
            surface: 'ssh_sudo',
          }),
        );

        assertCommandPolicy(
          evaluateSudoPolicy({
            command,
            sudo: target.host.sudo,
            surface: 'ssh_sudo',
            policyMode: policy.mode,
          }),
        );

        validateRemoteCommandInput({ command });

        const mode = target.host.sudo.mode;
        observedMode = mode;
        if (mode === 'off') {
          // evaluateSudoPolicy 已拒绝；保留防御性分支。
          assertCommandPolicy({
            action: 'deny',
            code: 'sudo_disabled',
            reason: 'sudo 已在配置中关闭',
            surface: 'ssh_sudo',
          });
          // assertCommandPolicy 必定抛错；这里显式收窄 mode 的类型。
          throw new Error('unreachable: sudo is disabled');
        }

        const remote = buildSudoRemoteCommand({
          command,
          mode,
          limits: {
            maxRemoteUtf16: DEFAULT_EXEC_LIMITS.maxRemoteUtf16,
            maxRemoteUtf8: DEFAULT_EXEC_LIMITS.maxRemoteUtf8,
          },
        });

        const timeoutMs = Math.min(
          input.timeout_ms ?? target.host.timeouts.commandMs,
          target.host.timeouts.commandMs,
        );
        const plan: SudoPlan = {
          remote,
          timeoutMs,
          maxOutputBytes: target.host.maxOutputBytes,
        };

        if (mode === 'password') {
          const name = target.host.sudo.credential;
          if (name === undefined) {
            plan.credentialError = makeToolError('Policy', {
              code: 'sudo_credential_missing',
              message: 'sudo.mode=password 但未配置 sudo.credential',
            });
          } else {
            try {
              const secret = await loadSecret(credentialProviderOf(ctx), name, {
                timeoutMs: CREDENTIAL_TIMEOUT_MS,
              });
              pendingCredential = secret;
              plan.credential = secret;
            } catch (err) {
              plan.credentialError = sudoCredentialFailure(err);
            }
          }
        }

        return plan;
      },
      execute: async ({ target, plan }) => {
        if (plan.credentialError !== undefined) {
          return { credentialError: plan.credentialError };
        }

        let stdin: Buffer | undefined;
        try {
          if (plan.remote.sudoMode === 'password') {
            const secret = plan.credential;
            if (secret === undefined) {
              return {
                credentialError: sudoCredentialFailure(
                  new CredentialError('credential_not_found', 'credential missing'),
                ),
              };
            }
            stdin = composeSudoStdin(secret.copy());
          }

          const run = await runSshCommand({
            host: target.host,
            knownHostsFile: ctx.paths.knownHostsFile,
            remoteCommand: plan.remote.remoteCommand,
            timeoutMs: plan.timeoutMs,
            maxOutputBytes: plan.maxOutputBytes,
            mode: 'strict',
            ...(stdin !== undefined ? { stdinData: stdin } : {}),
            label: `ssh_sudo:${target.host.alias}`,
          });
          return { run };
        } finally {
          stdin?.fill(0);
          plan.credential?.wipe();
        }
      },
      classifyFailure: (produced) => classifySudoFailure(produced, ctx.log),
      audit: async ({ target, plan, produced, lease, failure }) => {
        await appendAuditRecord(
          buildSudoAuditRecord({
            alias: target.host.alias,
            destination: target.destination,
            sudoMode: plan.remote.sudoMode,
            commandSha256: plan.remote.inner.commandSha256,
            commandBytes: plan.remote.inner.commandBytes,
            cwd: plan.remote.inner.cwd,
            envKeys: [],
            stdinBytes: 0,
            ...(produced.run !== undefined ? { run: produced.run } : {}),
            queueMs: lease.queueMs,
            ...(failure !== undefined
              ? { failure: { code: failure.code, kind: failure.kind, message: failure.message } }
              : {}),
          }),
          {
            configDir: ctx.paths.configDir,
            log: ctx.log,
            audit: target.config.security.audit,
          },
        );
      },
      format: ({ target, plan, produced, lease, failure }) => {
        const sudoMode = plan.remote.sudoMode;
        if (produced.run === undefined) {
          const err =
            failure ??
            produced.credentialError ??
            makeToolError('Internal', { code: 'internal_error', message: 'sudo 执行失败' });
          return sudoErrorResult(err, target.host.alias, sudoMode);
        }
        return formatExecResult({
          alias: target.host.alias,
          host: target.host,
          destination: target.destination,
          plan: plan.remote.inner,
          run: produced.run,
          queueMs: lease.queueMs,
          ...(failure !== undefined ? { failure } : {}),
          tool: 'ssh_sudo',
          extraStructured: { sudo_mode: sudoMode },
        });
      },
      auditDenied: async ({ phase, error, target }) => {
        if (phase !== 'prepare' || (error.kind !== 'Policy' && error.kind !== 'SudoPrompt')) {
          return;
        }
        const commandSha256 = sha256Hex(input.command);
        const commandBytes = Buffer.byteLength(input.command, 'utf8');
        const record = buildSudoAuditRecord({
          ...(target !== undefined
            ? { alias: target.host.alias, destination: target.destination }
            : {}),
          sudoMode: target?.host.sudo.mode ?? 'off',
          commandSha256,
          commandBytes,
          cwd: '~',
          envKeys: [],
          stdinBytes: 0,
          failure: { code: error.code, kind: error.kind },
        });
        await appendAuditRecord(record, {
          configDir: ctx.paths.configDir,
          log: ctx.log,
          ...(target !== undefined ? { audit: target.config.security.audit } : {}),
        });
      },
    });
  } catch (e) {
    // runSshOperation 已兜底；这里防御最后一条抛出路径。
    return sudoErrorResult(errorToToolError(e, ctx.log), input.host ?? 'unknown', observedMode);
  } finally {
    pendingCredential?.wipe();
  }
}

/** 保留导出以便测试检查门槛常量与 ssh_exec 一致。 */
export const SUDO_EXEC_LIMITS = EXEC_LIMITS;
