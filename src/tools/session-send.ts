import type { CallToolResult } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { sha256Hex } from '../audit/audit.js';
import { makeToolError } from '../errors/taxonomy.js';
import { evaluateCommandPolicy } from '../policy/command-policy.js';
import { buildSessionSendAudit } from '../session/audit.js';
import { formatSessionSend } from '../session/format.js';
import { validateSessionSendInput as validateSendInput } from '../policy/session.js';
import { effectiveHost } from '../policy/target.js';
import { checkTrust, trustFactToToolError } from '../pipeline/trust.js';
import type { Session } from '../session/session.js';
import type { RemoteConfig } from '../types.js';
import { toolErrorResult, type ToolContext } from './common.js';
import {
  appendSessionAudit,
  requireSession,
  sendOutcomeToToolError,
  sessionErrorToToolError,
  sessionRegistry,
} from './session-common.js';

export const sessionSendInput = z
  .object({
    session_id: z.string().min(1).max(64),
    command: z.string().min(1),
    timeout_ms: z.number().int().min(1).max(600_000).optional(),
    max_output_bytes: z.number().int().min(4096).max(8_388_608).optional(),
  })
  .strict();

export type SessionSendInput = z.infer<typeof sessionSendInput>;

/** 当前配置中该 alias 指向的 destination；alias 已不存在/非法时返回 undefined。 */
function currentDestination(config: RemoteConfig, alias: string): string | undefined {
  try {
    const host = effectiveHost(config, alias);
    return `${host.user}@${host.host}:${host.port}`;
  } catch {
    return undefined;
  }
}

/**
 * session_send：取会话 -> 校验 -> FIFO 执行（持有主机租约）-> 审计 -> 格式化。
 * 超时/协议/IO 失败返回 isError，但退出码非零仍是正常结果（与 ssh_exec 一致）。
 */
export async function sessionSend(
  input: SessionSendInput,
  ctx: ToolContext,
): Promise<CallToolResult> {
  let session: Session | undefined;
  try {
    session = requireSession(input.session_id);
    validateSendInput(input);

    // 命令策略先于目标/信任/发送求值：deny/confirm 不建立任何连接。
    const config = await ctx.getConfig();
    const decision = evaluateCommandPolicy({
      command: input.command,
      policy: config.security.commandPolicy,
      surface: 'session_send',
    });
    if (decision.action !== 'allow') {
      const error = makeToolError('Policy', {
        code: decision.code,
        message: decision.reason,
        details: {
          action: decision.action,
          code: decision.code,
          ruleId: decision.ruleId,
          surface: decision.surface,
          reason: decision.reason,
        },
      });
      await appendSessionAudit(
        buildSessionSendAudit({
          sessionId: session.id,
          alias: session.alias,
          destination: session.destination,
          cwd: session.cwd,
          commandSha256: sha256Hex(input.command),
          commandBytes: Buffer.byteLength(input.command, 'utf8'),
          outcome: 'denied',
          failure: { code: error.code, kind: error.kind },
        }),
        ctx,
        config.security.audit,
      );
      return toolErrorResult(error, session.alias, 'session_send');
    }

    // 会话可能存活很久：配置可能已把 alias 指向别处。先用建立会话时的
    // destination 与当前配置比对；不一致则拒绝，避免把命令发到新目标。
    const liveDestination = currentDestination(config, session.alias);
    if (liveDestination !== session.destination) {
      const reason = liveDestination === undefined ? 'trust_revoked' : 'alias_retargeted';
      const error = makeToolError('HostKey', {
        code: 'host_key',
        message:
          liveDestination === undefined
            ? `session ${session.id} alias ${session.alias} is no longer configured`
            : `session ${session.id} alias ${session.alias} now points to a different destination`,
        details: {
          reason,
          alias: session.alias,
          destination: session.destination,
          current_destination: liveDestination ?? null,
        },
      });
      await session.close(reason);
      sessionRegistry().delete(session.id);
      return toolErrorResult(error, session.alias, 'session_send');
    }

    // 信任复查使用会话建立时的 host 快照，而不是按当前 alias 重新解析。
    // 防止密钥被轮换/撤销后仍通过旧会话执行命令。
    const trust = await checkTrust({
      alias: session.host.alias,
      host: session.host,
      paths: ctx.paths,
      log: ctx.log,
    });
    if (!trust.ok) {
      const base = trustFactToToolError(trust.fact, ctx.log);
      const error = {
        ...base,
        details: {
          ...(base.details ?? {}),
          reason: trust.fact.reason ?? 'trust_revoked',
        },
      };
      await session.close('trust_revoked');
      // addClosedListener 通常已经移除；这里显式删除保证立即释放名额。
      sessionRegistry().delete(session.id);
      return toolErrorResult(error, session.alias, 'session_send');
    }

    const result = await session.send({
      command: input.command,
      ...(input.timeout_ms !== undefined ? { timeoutMs: input.timeout_ms } : {}),
      ...(input.max_output_bytes !== undefined
        ? { maxOutputBytes: input.max_output_bytes }
        : {}),
    });

    const outcome = result.outcome;
    const failure = sendOutcomeToToolError(session.id, outcome);
    const exitCode = outcome.status === 'ok' ? outcome.rc : null;

    await appendSessionAudit(
      buildSessionSendAudit({
        sessionId: session.id,
        alias: session.alias,
        destination: session.destination,
        cwd: session.cwd,
        seq: outcome.seq,
        commandSha256: sha256Hex(input.command),
        commandBytes: Buffer.byteLength(input.command, 'utf8'),
        exitCode,
        outputBytes: outcome.output.bytes,
        truncated: outcome.output.truncated,
        durationMs: outcome.duration_ms,
        queueMs: result.queueMs,
        sessionQueueMs: result.sessionQueueMs,
        ...(failure !== undefined
          ? { failure: { code: failure.code, kind: failure.kind } }
          : {}),
      }),
      ctx,
      config.security.audit,
    );

    if (failure !== undefined) {
      return toolErrorResult(failure, session.alias, 'session_send');
    }
    if (outcome.status !== 'ok') {
      // 防御：sendOutcomeToToolError 对非 ok 结果必定返回错误。
      return toolErrorResult(
        {
          kind: 'Internal',
          code: 'session_internal_error',
          message: 'session send produced no outcome',
          retryable: false,
        },
        session.alias,
        'session_send',
      );
    }

    return formatSessionSend({
      sessionId: session.id,
      alias: session.alias,
      destination: session.destination,
      exitCode: outcome.rc,
      output: outcome.output,
      durationMs: outcome.duration_ms,
      queueMs: result.queueMs,
      sessionQueueMs: result.sessionQueueMs,
    });
  } catch (e) {
    return toolErrorResult(
      sessionErrorToToolError(e, ctx.log),
      session?.alias,
      'session_send',
    );
  }
}
