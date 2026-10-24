import type { CallToolResult } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { validateSessionStartInput as validateStartInput } from '../policy/session.js';
import { renderCwd, renderEnvExports } from '../policy/remote-command.js';
import { runSshOperation } from '../pipeline/operation.js';
import type { ResolvedTarget } from '../pipeline/target.js';
import { buildSessionCloseAudit } from '../session/audit.js';
import { DEFAULT_IDLE_TIMEOUT_MS } from '../session/constants.js';
import { formatSessionStart } from '../session/format.js';
import { createNonce, newSessionId } from '../session/frame.js';
import type { SessionReservation } from '../session/registry.js';
import { createSession, type Session } from '../session/session.js';
import type { SessionTransport } from '../session/transport.js';
import { openSessionTransport, SessionStartError } from '../session/transport.js';
import { buildSessionStartAudit } from '../session/audit.js';
import type { ToolError } from '../types.js';
import {
  aliasOf,
  errorToToolError,
  toolErrorResult,
  type ToolContext,
} from './common.js';
import {
  appendSessionAudit,
  SESSION_START_ANNOTATIONS,
  sessionErrorToToolError,
  sessionRegistry,
  sessionStartErrorToToolError,
} from './session-common.js';

/** 握手在 ssh connect timeout 之外额外允许的时间。 */
const HANDSHAKE_EXTRA_MS = 10_000;

export const sessionStartInput = z
  .object({
    host: z.string().min(1).max(64).optional(),
    cwd: z.string().min(1).max(4096).optional(),
    env: z.record(z.string(), z.string()).optional(),
    idle_timeout_ms: z.number().int().min(1_000).max(86_400_000).optional(),
  })
  .strict();

export type SessionStartInput = z.infer<typeof sessionStartInput>;

interface StartPlan {
  id: string;
  /** 握手 nonce：只给传输层使用，createSession 不再接收。 */
  nonce: string;
  cwd: string;
  envKeys: string[];
  cwdExpr: string;
  envLines: string[];
  idleTimeoutMs: number;
  handshakeTimeoutMs: number;
  reservation?: SessionReservation;
  /** 容量预占失败（too_many_sessions）；execute 直接返回，不 spawn。 */
  reserveError?: ToolError;
}

type StartOutcome =
  | { ok: true; session: Session }
  | { ok: false; error: ToolError };

/**
 * session_start：校验 -> 目标/信任门禁 -> 预占名额 -> 建立 ssh 传输、等待 RDY ->
 * 创建会话并登记 -> 审计 -> 格式化。失败时释放预占并关闭半成品传输。
 */
export async function sessionStart(
  input: SessionStartInput,
  ctx: ToolContext,
): Promise<CallToolResult> {
  try {
    validateStartInput(input);
  } catch (e) {
    return toolErrorResult(errorToToolError(e, ctx.log), aliasOf(input), 'session_start');
  }

  const registry = sessionRegistry();

  return runSshOperation<StartPlan, StartOutcome>({
    input,
    ctx,
    toolName: 'session_start',
    prepare: (target: ResolvedTarget): StartPlan => {
      const cwd = input.cwd ?? target.host.cwd;
      const cwdExpr = renderCwd(cwd);
      const envLines = renderEnvExports(input.env);
      const plan: StartPlan = {
        id: newSessionId(),
        nonce: createNonce(),
        cwd,
        envKeys: Object.keys(input.env ?? {}).sort(),
        cwdExpr,
        envLines,
        idleTimeoutMs: input.idle_timeout_ms ?? DEFAULT_IDLE_TIMEOUT_MS,
        handshakeTimeoutMs: target.host.timeouts.connectMs + HANDSHAKE_EXTRA_MS,
      };
      try {
        plan.reservation = registry.beginStart(target.destination);
      } catch (e) {
        // 容量耗尽不是 spawn 失败：保留带会话提示/retryable 的错误，交给 execute 走
        // 统一的 audit/format 路径（不建立任何连接）。
        plan.reserveError = sessionErrorToToolError(e, ctx.log);
      }
      return plan;
    },
    execute: async ({ target, plan }): Promise<StartOutcome> => {
      if (plan.reserveError !== undefined) return { ok: false, error: plan.reserveError };
      if (plan.reservation === undefined) {
        return {
          ok: false,
          error: {
            kind: 'Internal',
            code: 'session_internal_error',
            message: 'session reservation was lost before start',
            retryable: false,
          },
        };
      }
      let transport: SessionTransport | undefined;
      try {
        transport = await openSessionTransport({
          host: target.host,
          destination: target.destination,
          knownHostsFile: ctx.paths.knownHostsFile,
          nonce: plan.nonce,
          cwdExpr: plan.cwdExpr,
          envLines: plan.envLines,
          handshakeTimeoutMs: plan.handshakeTimeoutMs,
          log: ctx.log,
        });
        let current: Session | undefined;
        current = createSession({
          id: plan.id,
          target: {
            alias: target.host.alias,
            destination: target.destination,
            defaultTimeoutMs: target.host.timeouts.commandMs,
            defaultMaxOutputBytes: target.host.maxOutputBytes,
          },
          transport,
          cwd: plan.cwd,
          envKeys: plan.envKeys,
          idleTimeoutMs: plan.idleTimeoutMs,
          maxQueue: registry.maxQueue,
          log: ctx.log,
          // 自关闭（idle/timeout/protocol/transport/shutdown）与显式关闭都经此写审计；
          // sessionClose 工具不再重复写，保证每个会话恰好一条 close 记录。
          onAuditClose: async (facts) => {
            const snapshot = current?.snapshot();
            await appendSessionAudit(
              buildSessionCloseAudit({
                sessionId: plan.id,
                alias: target.host.alias,
                destination: target.destination,
                cwd: plan.cwd,
                envKeys: plan.envKeys,
                commandsRun: snapshot?.commands_run ?? 0,
                outputBytes: snapshot?.output_bytes ?? 0,
                truncated: snapshot?.truncated ?? false,
                durationMs: facts.duration_ms,
                exitCode: facts.exit_code,
                signal: facts.signal,
                graceful: facts.graceful,
                killed: facts.killed,
                reason: facts.reason,
              }),
              ctx,
            );
          },
        });
        plan.reservation.commit(current);
        return { ok: true, session: current };
      } catch (e) {
        plan.reservation.abort();
        if (transport !== undefined) {
          try {
            await transport.close();
          } catch {
            // close 永不 reject；忽略半成品关闭错误。
          }
        }
        const error =
          e instanceof SessionStartError
            ? sessionStartErrorToToolError(e)
            : errorToToolError(e, ctx.log);
        return { ok: false, error };
      }
    },
    classifyFailure: (produced) => (produced.ok ? undefined : produced.error),
    audit: async ({ target, plan, produced, failure }) => {
      const sessionId = produced.ok ? produced.session.id : plan.id;
      await appendSessionAudit(
        buildSessionStartAudit({
          sessionId,
          alias: target.host.alias,
          destination: target.destination,
          cwd: plan.cwd,
          envKeys: plan.envKeys,
          idleTimeoutMs: plan.idleTimeoutMs,
          ...(failure !== undefined ? { failure: { code: failure.code, kind: failure.kind } } : {}),
        }),
        ctx,
      );
    },
    auditDenied: async ({ error, target }) => {
      await appendSessionAudit(
        buildSessionStartAudit({
          ...(target !== undefined
            ? { alias: target.host.alias, destination: target.destination }
            : input.host !== undefined
              ? { alias: input.host }
              : {}),
          failure: { code: error.code, kind: error.kind },
        }),
        ctx,
      );
    },
    format: ({ target, produced }) => {
      if (!produced.ok) {
        return toolErrorResult(produced.error, target.host.alias, 'session_start');
      }
      const session = produced.session;
      return formatSessionStart({
        sessionId: session.id,
        alias: session.alias,
        destination: session.destination,
        cwd: session.cwd,
        envKeys: session.envKeys,
        idleTimeoutMs: session.idleTimeoutMs,
      });
    },
  });
}
