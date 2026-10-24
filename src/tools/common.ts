import type { CallToolResult, McpServer, StandardSchemaWithJSON } from '@modelcontextprotocol/server';
import type { ZodType } from 'zod';
import type { CredentialProvider } from '../credentials/provider.js';
import { ConfigError, UsageError } from '../errors/classes.js';
import { formatToolError, toUserError } from '../errors/classify.js';
import { serializeError } from '../log.js';
import type { Logger, MCPPaths, RemoteConfig, ToolError } from '../types.js';

/** 工具运行时上下文。server.ts 通过 re-export 对外提供同名类型。 */
export interface ToolContext {
  paths: MCPPaths;
  log: Logger;
  getConfig: () => Promise<RemoteConfig>;
  /** 可选注入（测试/嵌入）；未定义时使用进程单例 keyring provider。 */
  credentialProvider?: CredentialProvider;
}

/** 文本内容 + 可选 structuredContent。 */
export function textResult(text: string, structured?: unknown): CallToolResult {
  const result: CallToolResult = { content: [{ type: 'text', text }] };
  if (structured !== undefined) {
    result.structuredContent = structured as Record<string, unknown>;
  }
  return result;
}

/**
 * 工具级错误结果（isError: true）。绝不抛出。
 * structuredContent 统一为 `{tool?, host?, error}`，与各工具自己的失败格式一致。
 */
export function toolErrorResult(err: ToolError, alias?: string, tool?: string): CallToolResult {
  const result: CallToolResult = {
    content: [{ type: 'text', text: formatToolError(err, alias) }],
    isError: true,
    structuredContent: {
      ...(tool !== undefined ? { tool } : {}),
      ...(alias !== undefined ? { host: alias } : {}),
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
  } else if (typeof e.code === 'string' && e.code !== '') {
    code = e.code;
  }
  // reason 只用于挑选 REASON_HINTS；Policy 类别由 phase=config 决定
  const base = toUserError({ phase: 'config', reason: code });
  const error: ToolError = { ...base, code, message: e.message };
  // 保留策略细节（action/code/ruleId/surface/reason），与 session_send 的约定一致。
  const details =
    e instanceof UsageError
      ? (e as UsageError & { details?: Record<string, unknown> }).details
      : undefined;
  if (details !== undefined) {
    error.details = details;
    // 策略层可在 details.hint 中提供更具体的说明（如 ssh_sudo 的剥离拒绝原因）。
    const detailHint = details['hint'];
    if (typeof detailHint === 'string') error.hint = detailHint;
  }
  return error;
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

/** MCP tool annotation hints; omitted hints keep the protocol default. */
export interface ToolAnnotations {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

export interface ToolDefinition<I> {
  name: string;
  title: string;
  description: string;
  inputSchema: ZodType<I>;
  annotations?: ToolAnnotations;
  handler: (input: I, ctx: ToolContext) => Promise<CallToolResult>;
}

/** 错误渲染用：同时识别 `alias` 与 `host` 两种输入字段名。 */
export function aliasOf(args: unknown): string | undefined {
  if (typeof args !== 'object' || args === null) return undefined;
  const record = args as Record<string, unknown>;
  for (const key of ['alias', 'host']) {
    const v = record[key];
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
      annotations: def.annotations ?? { readOnlyHint: true },
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
        return toolErrorResult(err, alias, def.name);
      }
    },
  );
}
