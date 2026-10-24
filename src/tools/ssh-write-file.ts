import type { CallToolResult } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { UsageError } from '../errors/classes.js';
import { runSshOperation } from '../pipeline/operation.js';
import type { ResolvedTarget } from '../pipeline/target.js';
import { hasLoneSurrogate } from '../policy/shell.js';
import {
  assertRemotePathAllowed,
  buildRemoteDenyLists,
  normalizeRemotePath,
} from '../policy/remote-path.js';
import { assertFileSize, fileLimitsFrom } from '../transfer/file-policy.js';
import { writeRemoteFile, type WriteFacts } from '../transfer/remote-file.js';
import type { ToolContext } from './common.js';
import {
  appendTransferAudit,
  makeTransferDeps,
} from './transfer-common.js';
import { formatWriteFileResult } from './transfer-format.js';

const MAX_CONTENT_CHARS = 16 * 1024 * 1024;

export const sshWriteFileInput = z
  .object({
    host: z.string().min(1).max(64).optional(),
    path: z.string().min(1).max(4096),
    content: z.string().max(MAX_CONTENT_CHARS),
    encoding: z.enum(['utf8', 'base64']).optional(),
    /** 八进制字符串（如 "0640"）或整数；特殊位会被掩掉。 */
    mode: z.union([z.string(), z.number().int()]).optional(),
    overwrite: z.boolean().optional(),
  })
  .strict();

export type SshWriteFileInput = z.infer<typeof sshWriteFileInput>;

export interface WritePlan {
  remote: string;
  remoteRaw: string;
  content: Buffer;
  encoding: 'utf8' | 'base64';
  mode?: number;
  overwrite: boolean;
  denyWrite: string[];
  timeoutMs: number;
}

function contentError(code: string, message: string): UsageError {
  return new UsageError(message, { code });
}

/** 严格 base64：长度、字符集与规范化往返都必须一致。 */
export function decodeBase64Content(text: string): Buffer {
  if (text.length === 0) return Buffer.alloc(0);
  if (text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    throw contentError('content_invalid_base64', 'content is not valid base64');
  }
  const buf = Buffer.from(text, 'base64');
  if (buf.toString('base64') !== text) {
    throw contentError('content_invalid_base64', 'content is not canonical base64');
  }
  return buf;
}

export function decodeContent(
  content: string,
  encoding: 'utf8' | 'base64',
): Buffer {
  if (encoding === 'base64') return decodeBase64Content(content);
  if (hasLoneSurrogate(content)) {
    throw contentError('content_invalid_utf8', 'content contains lone UTF-16 surrogates');
  }
  return Buffer.from(content, 'utf8');
}

/** mode：字符串按八进制解析（可带前导 0），数字按整数；最终掩到 0o777。 */
export function parseModeInput(value: string | number | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0 || value > 0o7777) {
      throw contentError('mode_invalid', 'mode must be an integer between 0 and 7777');
    }
    return value & 0o777;
  }
  if (!/^0?[0-7]{3,4}$/.test(value)) {
    throw contentError('mode_invalid', 'mode must be an octal string such as "0640"');
  }
  return Number.parseInt(value, 8) & 0o777;
}

/**
 * prepare：解码（utf8/base64）-> 限额 -> 远端路径规范化与写 deny -> mode 归一。
 * 不 spawn。
 */
export function buildWritePlan(input: SshWriteFileInput, target: ResolvedTarget): WritePlan {
  const files = target.config.files;
  const encoding = input.encoding ?? 'utf8';
  const content = decodeContent(input.content, encoding);
  assertFileSize(content.length, fileLimitsFrom(files), 'content');

  const normalized = normalizeRemotePath(input.path, target.host.cwd);
  const denyWrite = buildRemoteDenyLists(files).write;
  assertRemotePathAllowed(normalized.absolute, 'write', denyWrite);
  const mode = parseModeInput(input.mode);

  return {
    remote: normalized.absolute,
    remoteRaw: input.path,
    content,
    encoding,
    ...(mode !== undefined ? { mode } : {}),
    overwrite: input.overwrite === true,
    denyWrite,
    timeoutMs: files.transferTimeoutMs,
  };
}

/**
 * ssh_write_file：写入远端文件。内容在本地解码与限额，远端使用同目录临时文件 +
 * sha256 校验 + chmod + 原子换入；失败不会留下半写文件。
 */
export async function sshWriteFile(
  input: SshWriteFileInput,
  ctx: ToolContext,
): Promise<CallToolResult> {
  return runSshOperation<WritePlan, WriteFacts>({
    input,
    ctx,
    toolName: 'ssh_write_file',
    prepare: (target) => buildWritePlan(input, target),
    execute: ({ target, plan }) =>
      writeRemoteFile({
        deps: makeTransferDeps(target, ctx),
        remote: plan.remote,
        content: plan.content,
        encoding: plan.encoding,
        ...(plan.mode !== undefined ? { mode: plan.mode } : {}),
        overwrite: plan.overwrite,
        denyWrite: plan.denyWrite,
        timeoutMs: plan.timeoutMs,
      }),
    classifyFailure: (facts) => facts.failure,
    auditDenied: async ({ ctx: auditCtx, error, target }) => {
      await appendTransferAudit({
        tool: 'ssh_write_file',
        ctx: auditCtx,
        input,
        direction: 'upload',
        ...(target !== undefined ? { target } : {}),
        targetPath: input.path,
        failure: error,
        denied: true,
      });
    },
    audit: async ({ target, plan, produced, lease }) => {
      await appendTransferAudit({
        tool: 'ssh_write_file',
        ctx,
        input,
        direction: 'upload',
        target,
        sourcePath: undefined,
        targetPath: produced.path,
        facts: {
          ok: produced.ok,
          ...(produced.failure !== undefined ? { failure: produced.failure } : {}),
          files: produced.ok ? 1 : 0,
          bytes: produced.ok ? produced.bytes : 0,
          verified: produced.verified,
          ...(produced.run !== undefined ? { run: produced.run } : {}),
        },
        queueMs: lease.queueMs,
      });
    },
    format: ({ target, produced, lease }) =>
      formatWriteFileResult({
        host: target.host.alias,
        facts: produced,
        queueMs: lease.queueMs,
      }),
  });
}
