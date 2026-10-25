import type { ResolvedTarget } from '../pipeline/target.js';
import { renderCwd } from '../policy/remote-command.js';
import { createNonce, newSessionId } from '../session/frame.js';
import { createSession, type Session } from '../session/session.js';
import {
  openSessionTransport,
  type SessionTransport,
} from '../session/transport.js';
import type { CapturedOutput, SendOutcome } from '../session/types.js';
import type { Logger } from '../types.js';
import type {
  TransferControl,
  TransferControlResult,
  TransferControlRunOptions,
} from './deps.js';

/** 握手在 ssh connect timeout 之外额外允许的时间（与 session_start 一致）。 */
const HANDSHAKE_EXTRA_MS = 10_000;
/**
 * 内部会话的空闲兜底。传输期间两条控制命令之间可能隔着很长的 sftp/tar
 * 数据面传输，因此不能按交互式会话的短空闲超时来算；真正的生命周期由
 * 调用方在 finally 中显式 close 决定。
 */
const IDLE_GRACE_MS = 60_000;

export interface OpenTransferControlOptions {
  target: ResolvedTarget;
  knownHostsFile: string;
  log: Logger;
  /** 会话启动目录；默认 target.host.cwd。 */
  cwd?: string;
}

/** 传输控制通道句柄：run 执行控制命令，close 释放常驻会话。 */
export interface TransferControlHandle extends TransferControl {
  readonly sessionId: string;
  /** 幂等；永不 reject（失败只记 warn）。 */
  close(reason?: string): Promise<void>;
}

/** 控制会话在命令结束前关闭/协议错误。 */
export class TransferControlError extends Error {
  readonly reason: 'closed' | 'error';

  constructor(message: string, reason: 'closed' | 'error') {
    super(message);
    this.name = 'TransferControlError';
    this.reason = reason;
  }
}

/**
 * 会话循环在同一个 shell 中 eval 命令；传输脚本用 `exit <code>` 表达状态
 * （probe 的 3、swap 的 1/2/3），裸 exit 会终止整个会话。用子 shell 隔离，
 * 子 shell 的退出码即 E 帧的 rc，标准输出/错误仍被会话捕获。
 */
export function wrapControlCommand(command: string): string {
  return `(\n${command}\n)`;
}

/** 会话输出 -> 文本；含 NUL/非 UTF-8 时 capture 给的是 base64。 */
function decodeOutput(output: CapturedOutput): string {
  return output.encoding === 'base64'
    ? Buffer.from(output.text, 'base64').toString('utf8')
    : output.text;
}

function mapOutcome(outcome: SendOutcome): TransferControlResult {
  const stdout = decodeOutput(outcome.output);
  if (outcome.status === 'ok') {
    return {
      exitCode: outcome.rc,
      stdout,
      timedOut: false,
      durationMs: outcome.duration_ms,
    };
  }
  if (outcome.status === 'timeout') {
    return {
      exitCode: null,
      stdout,
      timedOut: true,
      durationMs: outcome.duration_ms,
    };
  }
  if (outcome.status === 'closed') {
    throw new TransferControlError(
      'transfer control session closed before the command finished',
      'closed',
    );
  }
  throw new TransferControlError(outcome.message, 'error');
}

function controlIdleTimeoutMs(target: ResolvedTarget): number {
  return Math.max(IDLE_GRACE_MS, target.config.files.transferTimeoutMs + IDLE_GRACE_MS);
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * 建立传输用的内部持久控制会话。
 *
 * - 不登记到 session registry，因此不出现在 session_list，也不占会话名额；
 * - 不写 close 审计（传输本身已有审计，避免重复）；
 * - skipLease：外层 transfer execute 已持有 host lease，避免嵌套租约死锁；
 * - 握手/启动失败时关闭半成品传输并返回 undefined，调用方回退到一次性
 *   `runRemoteCommand`，不改变正确性。
 */
export async function openTransferControl(
  opts: OpenTransferControlOptions,
): Promise<TransferControlHandle | undefined> {
  const { target, knownHostsFile, log } = opts;
  const cwd = opts.cwd ?? target.host.cwd;
  const nonce = createNonce();
  let transport: SessionTransport | undefined;

  try {
    transport = await openSessionTransport({
      host: target.host,
      destination: target.destination,
      knownHostsFile,
      nonce,
      cwdExpr: renderCwd(cwd),
      envLines: [],
      handshakeTimeoutMs: target.host.timeouts.connectMs + HANDSHAKE_EXTRA_MS,
      log,
    });

    const session: Session = createSession({
      id: newSessionId(),
      target: {
        alias: target.host.alias,
        destination: target.destination,
        // 快照建立会话时的有效主机；内部会话不再做信任复查。
        host: target.host,
        defaultTimeoutMs: target.host.timeouts.commandMs,
        defaultMaxOutputBytes: target.host.maxOutputBytes,
      },
      transport,
      cwd,
      envKeys: [],
      idleTimeoutMs: controlIdleTimeoutMs(target),
      nonce,
      log,
      skipLease: true,
      // 不设置 onClosed / onAuditClose：内部会话不进入登记簿，也不写会话审计。
    });

    return {
      sessionId: session.id,
      async run(command: string, runOpts: TransferControlRunOptions): Promise<TransferControlResult> {
        const sent = await session.send({
          command: wrapControlCommand(command),
          timeoutMs: runOpts.timeoutMs,
          maxOutputBytes: runOpts.maxOutputBytes,
        });
        return mapOutcome(sent.outcome);
      },
      async close(reason = 'transfer_complete'): Promise<void> {
        try {
          await session.close(reason);
        } catch (err) {
          try {
            log.warn(
              { err: errorMessage(err), destination: target.destination },
              'transfer control session close failed',
            );
          } catch {
            // 日志失败不影响调用方
          }
        }
      },
    };
  } catch (err) {
    if (transport !== undefined) {
      try {
        await transport.close();
      } catch {
        // close 永不 reject；忽略半成品关闭错误。
      }
    }
    try {
      log.warn(
        { err: errorMessage(err), destination: target.destination },
        'transfer control session unavailable; falling back to one-shot ssh',
      );
    } catch {
      // 日志失败不影响回退
    }
    return undefined;
  }
}
