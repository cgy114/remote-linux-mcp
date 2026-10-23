import type { CallToolResult } from '@modelcontextprotocol/server';
import { formatToolError } from '../errors/classify.js';
import type { ReadFacts, WriteFacts } from '../transfer/remote-file.js';
import type { TransferFacts } from '../transfer/single-file.js';
import type { ToolError } from '../types.js';
import { textResult } from './common.js';

function modeText(mode: number): string {
  return (mode & 0o777).toString(8).padStart(3, '0');
}

function failureResult(tool: string, host: string, failure: ToolError): CallToolResult {
  return {
    content: [{ type: 'text', text: formatToolError(failure, host) }],
    isError: true,
    structuredContent: {
      tool,
      host,
      error: {
        kind: failure.kind,
        code: failure.code,
        message: failure.message,
        hint: failure.hint,
        ...(failure.details !== undefined ? { details: failure.details } : {}),
      },
    },
  };
}

export interface FormatTransferInput {
  tool: string;
  host: string;
  facts: TransferFacts;
  queueMs?: number;
}

/**
 * upload/download 的结果格式化。失败只输出 kind/code/message/hint；
 * 成功输出文件数、字节数、摘要与原子替换事实。
 */
export function formatTransferResult(input: FormatTransferInput): CallToolResult {
  const { facts, tool, host } = input;
  if (!facts.ok) {
    return failureResult(tool, host, facts.failure ?? {
      kind: 'Internal',
      code: 'transfer_failed',
      message: 'file transfer failed',
      retryable: false,
    });
  }

  const fileWord = facts.files === 1 ? 'file' : 'files';
  const lines = [
    `${tool}: OK (${facts.kind}, ${facts.files} ${fileWord}, ${facts.bytes} bytes, ${facts.durationMs}ms)`,
    `host: ${host}`,
    `source: ${facts.sourcePath}`,
    `target: ${facts.targetPath}`,
    `verified: ${facts.kind === 'directory' ? 'manifest' : 'sha256+size'}`,
    `atomic_replace: yes, overwritten: ${facts.overwritten ? 'yes' : 'no'}`,
  ];
  if (facts.sha256 !== undefined) lines.push(`sha256: ${facts.sha256}`);
  if (facts.manifestDigest !== undefined) lines.push(`manifest: ${facts.manifestDigest}`);

  const structured: Record<string, unknown> = {
    tool,
    host,
    ok: true,
    direction: facts.direction,
    kind: facts.kind,
    source_path: facts.sourcePath,
    target_path: facts.targetPath,
    file_count: facts.files,
    bytes: facts.bytes,
    sha256: facts.sha256 ?? null,
    manifest_digest: facts.manifestDigest ?? null,
    verified: facts.verified,
    atomic_replace: facts.atomicReplace,
    overwritten: facts.overwritten,
    duration_ms: facts.durationMs,
    queue_ms: input.queueMs ?? 0,
  };
  return textResult(lines.join('\n'), structured);
}

export interface FormatReadFileInput {
  host: string;
  facts: ReadFacts;
  queueMs?: number;
}

/** ssh_read_file：内容按 encoding 返回（utf8 文本或 base64），其余只含摘要。 */
export function formatReadFileResult(input: FormatReadFileInput): CallToolResult {
  const { facts, host } = input;
  if (!facts.ok) {
    return failureResult('ssh_read_file', host, facts.failure ?? {
      kind: 'Internal',
      code: 'remote_read_failed',
      message: 'remote file read failed',
      retryable: false,
    });
  }

  const contentText = facts.encoding === 'utf8'
    ? facts.content.toString('utf8')
    : facts.content.toString('base64');
  const lines = [
    `ssh_read_file: OK (${facts.encoding}, ${facts.returnedBytes} of ${facts.size} bytes, ` +
      `truncated: ${facts.truncated ? 'yes' : 'no'}, ${facts.durationMs}ms)`,
    `host: ${host}`,
    `path: ${facts.path}`,
    `size: ${facts.size}`,
    `encoding: ${facts.encoding}`,
    ...(facts.sha256 !== undefined ? [`sha256: ${facts.sha256}`] : []),
    ...(facts.mode !== undefined ? [`mode: ${modeText(facts.mode)}`] : []),
    facts.encoding === 'utf8' ? '--- content ---' : '--- content (base64) ---',
    contentText,
  ];

  return textResult(lines.join('\n'), {
    tool: 'ssh_read_file',
    host,
    ok: true,
    path: facts.path,
    size: facts.size,
    sha256: facts.sha256 ?? null,
    mode: facts.mode ?? null,
    encoding: facts.encoding,
    content: contentText,
    returned_bytes: facts.returnedBytes,
    truncated: facts.truncated,
    duration_ms: facts.durationMs,
    queue_ms: input.queueMs ?? 0,
  });
}

export interface FormatWriteFileInput {
  host: string;
  facts: WriteFacts;
  queueMs?: number;
}

export function formatWriteFileResult(input: FormatWriteFileInput): CallToolResult {
  const { facts, host } = input;
  if (!facts.ok) {
    return failureResult('ssh_write_file', host, facts.failure ?? {
      kind: 'Internal',
      code: 'remote_write_failed',
      message: 'remote file write failed',
      retryable: false,
    });
  }

  const lines = [
    `ssh_write_file: OK (${facts.bytes} bytes, mode ${facts.mode !== undefined ? modeText(facts.mode) : 'unknown'}, ${facts.durationMs}ms)`,
    `host: ${host}`,
    `path: ${facts.path}`,
    `encoding: ${facts.encoding}`,
    ...(facts.sha256 !== undefined ? [`sha256: ${facts.sha256}`] : []),
    `verified: yes, atomic_replace: yes, overwritten: ${facts.overwritten ? 'yes' : 'no'}`,
  ];

  return textResult(lines.join('\n'), {
    tool: 'ssh_write_file',
    host,
    ok: true,
    path: facts.path,
    bytes: facts.bytes,
    sha256: facts.sha256 ?? null,
    encoding: facts.encoding,
    mode: facts.mode ?? null,
    verified: facts.verified,
    atomic_replace: facts.atomicReplace,
    overwritten: facts.overwritten,
    duration_ms: facts.durationMs,
    queue_ms: input.queueMs ?? 0,
  });
}
