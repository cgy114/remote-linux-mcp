import type { CallToolResult } from '@modelcontextprotocol/server';
import { textResult } from '../tools/common.js';
import type { CapturedOutput, CloseFacts, Snapshot } from './types.js';

/** 成功结果：显式 isError=false，与 ssh_exec 等工具保持一致。 */
function successResult(text: string, structured?: unknown): CallToolResult {
  const result = textResult(text, structured);
  result.isError = false;
  return result;
}

function stripTrailingNewline(text: string): string {
  if (text.endsWith('\r\n')) return text.slice(0, -2);
  if (text.endsWith('\n')) return text.slice(0, -1);
  return text;
}

export interface SessionStartView {
  sessionId: string;
  alias: string;
  destination: string;
  cwd: string;
  envKeys: readonly string[];
  idleTimeoutMs: number;
}

/** session_start 的文本 + structuredContent（不含 nonce/env 值）。 */
export function formatSessionStart(view: SessionStartView): CallToolResult {
  const lines = [
    `session ${view.sessionId} started (${view.alias}, ${view.destination})`,
    `cwd: ${view.cwd}`,
    `idle_timeout_ms: ${view.idleTimeoutMs}`,
  ];
  if (view.envKeys.length > 0) lines.push(`env_keys: ${view.envKeys.join(', ')}`);

  return successResult(lines.join('\n'), {
    tool: 'session_start',
    session_id: view.sessionId,
    host: view.alias,
    destination: view.destination,
    cwd: view.cwd,
    env_keys: [...view.envKeys],
    idle_timeout_ms: view.idleTimeoutMs,
  });
}

export interface SessionSendView {
  sessionId: string;
  alias: string;
  destination: string;
  exitCode: number;
  output: CapturedOutput;
  durationMs: number;
  queueMs: number;
  sessionQueueMs: number;
}

/** session_send 的结果：输出 + 退出码 + 两级排队时间。 */
export function formatSessionSend(view: SessionSendView): CallToolResult {
  const meta = [
    `${view.durationMs}ms`,
    `host-queue ${view.queueMs}ms`,
    `session-queue ${view.sessionQueueMs}ms`,
  ];
  const lines = [`session ${view.sessionId}: exit=${view.exitCode} (${meta.join(', ')})`];
  if (view.output.text.length > 0) {
    lines.push('output:', stripTrailingNewline(view.output.text));
  }
  if (view.output.truncated) lines.push('[output truncated]');

  return successResult(lines.join('\n'), {
    tool: 'session_send',
    session_id: view.sessionId,
    host: view.alias,
    destination: view.destination,
    exit_code: view.exitCode,
    output: view.output.text,
    encoding: view.output.encoding,
    bytes: view.output.bytes,
    truncated: view.output.truncated,
    duration_ms: view.durationMs,
    queue_ms: view.queueMs,
    session_queue_ms: view.sessionQueueMs,
  });
}

export interface SessionCloseView {
  sessionId: string;
  alias: string;
  destination: string;
  facts: CloseFacts;
}

/** session_close 的退出事实。 */
export function formatSessionClose(view: SessionCloseView): CallToolResult {
  const { facts } = view;
  const text =
    `session ${view.sessionId} closed ` +
    `(exit=${facts.exit_code === null ? 'null' : String(facts.exit_code)}, ` +
    `graceful=${String(facts.graceful)}, killed=${String(facts.killed)}, ${facts.duration_ms}ms)`;

  return successResult(text, {
    tool: 'session_close',
    session_id: view.sessionId,
    host: view.alias,
    destination: view.destination,
    exit_code: facts.exit_code,
    signal: facts.signal,
    graceful: facts.graceful,
    killed: facts.killed,
    duration_ms: facts.duration_ms,
  });
}

export interface SessionListEntry {
  sessionId: string;
  alias: string;
  destination: string;
  snapshot: Snapshot;
}

/**
 * session_list：只暴露状态快照。刻意不包含命令、输出内容与 nonce；
 * destination 是 user@host:port，alias 单独给出。
 */
export function formatSessionList(entries: readonly SessionListEntry[]): CallToolResult {
  const structured = {
    tool: 'session_list',
    count: entries.length,
    sessions: entries.map((entry) => {
      const snapshot = entry.snapshot;
      return {
        session_id: entry.sessionId,
        host: entry.alias,
        destination: entry.destination,
        state: snapshot.state,
        created_at: snapshot.created_at,
        last_activity_at: snapshot.last_activity_at,
        idle_timeout_ms: snapshot.idle_timeout_ms,
        queue_depth: snapshot.queue_depth,
        commands_run: snapshot.commands_run,
        output_bytes: snapshot.output_bytes,
        truncated: snapshot.truncated,
      };
    }),
  };

  if (entries.length === 0) {
    return successResult('no active sessions', structured);
  }

  const lines = entries.map((entry) => {
    const s = entry.snapshot;
    return (
      `${entry.sessionId} ${entry.alias} ${entry.destination} state=${s.state} ` +
      `queue=${s.queue_depth} commands=${s.commands_run} output_bytes=${s.output_bytes}` +
      `${s.truncated ? ' truncated' : ''}`
    );
  });
  return successResult(lines.join('\n'), structured);
}
