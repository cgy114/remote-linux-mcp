import type { CallToolResult, McpServer, StandardSchemaWithJSON } from '@modelcontextprotocol/server';
import type { ZodType } from 'zod';
import { ConfigError, UsageError } from '../errors/classes.js';
import { formatToolError, toUserError } from '../errors/classify.js';
import { serializeError } from '../log.js';
import type { Logger, MCPPaths, RemoteConfig, ToolError } from '../types.js';

/** 工具运行时上下文。server.ts 通过 re-export 对外提供同名类型。 */
export interface ToolContext {
  paths: MCPPaths;
  log: Logger;
  getConfig: () => Promise<RemoteConfig>;
}

/** 文本内容 + 可选 structuredContent。 */
export function textResult(text: string, structured?: unknown): CallToolResult {
  const result: CallToolResult = { content: [{ type: 'text', text }] };
  if (structured !== undefined) {
    result.structuredContent = structured as Record<string, unknown>;
  }
  return result;
}

/** 工具级错误结果（isError: true）。绝不抛出。 */
export function toolErrorResult(err: ToolError, alias?: string): CallToolResult {
  const result: CallToolResult = {
    content: [{ type: 'text', text: formatToolError(err, alias) }],
    isError: true,
    structuredContent: {
      error: {
        kind: err.kind,
        code: err.code,
        message: err.message,
        hint: err.hint,
        retryable: err.retryable,
        details: err.details,
      },
    },
  };
  return result;
}

/** UsageError / ConfigError -> Policy。保留原始 message，code 取自 UsageError.code 或 config_<code>。 */
export function policyError(e: UsageError | ConfigError): ToolError {
  let code = 'policy_denied';
  if (e instanceof ConfigError) {
    code = `config_${e.code}`;
  } else {
    const raw = (e as { code?: unknown }).code;
    if (typeof raw === 'string' && raw !== '') code = raw;
  }
  // reason 只用于挑选 REASON_HINTS；Policy 类别由 phase=config 决定
  const base = toUserError({ phase: 'config', reason: code });
  return { ...base, code, message: e.message };
}

/** 任意异常 -> ToolError。Policy 类异常保留消息；其余记录日志并返回 Internal。 */
export function errorToToolError(e: unknown, log?: Logger): ToolError {
  if (e instanceof UsageError || e instanceof ConfigError) {
    return policyError(e);
  }
  try {
    log?.error({ err: serializeError(e) }, 'unexpected tool error');
  } catch {
    // 日志失败不影响错误返回
  }
  return toUserError({ phase: 'probe', spawnError: { code: 'internal', message: String(e) } });
}

export interface ToolDefinition<I> {
  name: string;
  title: string;
  description: string;
  inputSchema: ZodType<I>;
  handler: (input: I, ctx: ToolContext) => Promise<CallToolResult>;
}

function aliasOf(args: unknown): string | undefined {
  if (typeof args === 'object' && args !== null && 'alias' in args) {
    const v = (args as { alias?: unknown }).alias;
    if (typeof v === 'string') return v;
  }
  return undefined;
}

/**
 * 注册只读工具。handler 的任何异常都被转换为 isError 结果，不会穿透到传输层。
 * 开始/结束与耗时只写入 ctx.log（stderr）。
 */
export function registerTool<I>(server: McpServer, def: ToolDefinition<I>, ctx: ToolContext): void {
  const log = ctx.log.child({ tool: def.name });
  server.registerTool(
    def.name,
    {
      title: def.title,
      description: def.description,
      inputSchema: def.inputSchema as unknown as StandardSchemaWithJSON,
      annotations: { readOnlyHint: true },
    },
    async (args: unknown): Promise<CallToolResult> => {
      const started = Date.now();
      log.debug('tool call started');
      try {
        const result = await def.handler(args as I, ctx);
        log.info({ durationMs: Date.now() - started, isError: result.isError === true }, 'tool call finished');
        return result;
      } catch (e) {
        const err = errorToToolError(e, log);
        log.info(
          { durationMs: Date.now() - started, kind: err.kind, code: err.code },
          'tool call failed',
        );
        const alias = aliasOf(args);
        return toolErrorResult(err, alias);
      }
    },
  );
}
