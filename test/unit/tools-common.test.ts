import type { CallToolResult, McpServer } from '@modelcontextprotocol/server';
import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { ConfigError, UsageError } from '../../src/errors/classes.js';
import {
  aliasOf,
  policyError,
  registerTool,
  toolErrorResult,
  type ToolContext,
} from '../../src/tools/common.js';
import type { Logger, MCPPaths } from '../../src/types.js';

describe('policyError', () => {
  it('uses the UsageError code and preserves the message', () => {
    expect(policyError(new UsageError('bad alias', { code: 'invalid_alias' }))).toMatchObject({
      kind: 'Policy',
      code: 'invalid_alias',
      message: 'bad alias',
    });
  });

  it('falls back to policy_denied when a UsageError carries no code', () => {
    expect(policyError(new UsageError('nope')).code).toBe('policy_denied');
  });

  it('maps ConfigError codes to config_<code>', () => {
    expect(policyError(new ConfigError('schema', 'bad')).code).toBe('config_schema');
    expect(policyError(new ConfigError('io', 'bad')).code).toBe('config_io');
  });
});

describe('toolErrorResult', () => {
  const error = {
    kind: 'Policy' as const,
    code: 'target_exists',
    message: 'already exists',
    hint: 'pass overwrite=true',
    retryable: false,
  };

  it('includes tool and host when provided', () => {
    const result = toolErrorResult(error, 'web1', 'ssh_upload');
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toEqual({
      tool: 'ssh_upload',
      host: 'web1',
      error: {
        kind: 'Policy',
        code: 'target_exists',
        message: 'already exists',
        hint: 'pass overwrite=true',
        retryable: false,
        details: undefined,
      },
    });
  });

  it('omits tool/host when not provided', () => {
    const structured = toolErrorResult(error).structuredContent as Record<string, unknown>;
    expect(Object.keys(structured)).toEqual(['error']);
    expect((structured['error'] as Record<string, unknown>)['retryable']).toBe(false);
  });
});

describe('aliasOf', () => {
  it('recognises alias and host fields', () => {
    expect(aliasOf({ alias: 'web' })).toBe('web');
    expect(aliasOf({ host: 'web1' })).toBe('web1');
    expect(aliasOf({ alias: 'a', host: 'b' })).toBe('a');
  });

  it('returns undefined for missing or non-string values', () => {
    expect(aliasOf({})).toBeUndefined();
    expect(aliasOf(null)).toBeUndefined();
    expect(aliasOf('web1')).toBeUndefined();
    expect(aliasOf({ alias: 1, host: 2 })).toBeUndefined();
  });
});

function makeLogger(): Logger {
  const logger: Logger = {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    child: () => logger,
  };
  return logger;
}

function makeCtx(): ToolContext {
  return {
    paths: {} as MCPPaths,
    log: makeLogger(),
    getConfig: async () => {
      throw new Error('unused in this test');
    },
  };
}

interface CapturedRegistration {
  name: string;
  options: { annotations?: Record<string, boolean> };
  handler: (args: unknown) => Promise<CallToolResult>;
}

function captureServer(): { server: McpServer; captured: () => CapturedRegistration } {
  let entry: CapturedRegistration | undefined;
  const server = {
    registerTool(
      name: string,
      options: CapturedRegistration['options'],
      handler: CapturedRegistration['handler'],
    ): void {
      entry = { name, options, handler };
    },
  } as unknown as McpServer;
  return { server, captured: () => entry as CapturedRegistration };
}

describe('registerTool annotations', () => {
  it('defaults to readOnlyHint: true', () => {
    const { server, captured } = captureServer();
    registerTool(
      server,
      {
        name: 't',
        title: 'T',
        description: 'd',
        inputSchema: z.object({}),
        handler: async () => ({ content: [] }),
      },
      makeCtx(),
    );
    expect(captured().options.annotations).toEqual({ readOnlyHint: true });
  });

  it('uses explicit annotations verbatim', () => {
    const annotations = { readOnlyHint: false, destructiveHint: true, openWorldHint: false };
    const { server, captured } = captureServer();
    registerTool(
      server,
      {
        name: 't',
        title: 'T',
        description: 'd',
        inputSchema: z.object({}),
        annotations,
        handler: async () => ({ content: [] }),
      },
      makeCtx(),
    );
    expect(captured().options.annotations).toBe(annotations);
  });
});

describe('registerTool error rendering', () => {
  it('uses a host-style argument as the rendered alias', async () => {
    const { server, captured } = captureServer();
    registerTool(
      server,
      {
        name: 't',
        title: 'T',
        description: 'd',
        inputSchema: z.object({ host: z.string() }),
        handler: async () => {
          throw new UsageError('boom', { code: 'invalid_host' });
        },
      },
      makeCtx(),
    );

    const result = await captured().handler({ host: 'web1' });
    const text = (result.content[0] as { text: string }).text;
    expect(result.isError).toBe(true);
    expect(text).toContain('host: web1');
    expect(text).toContain('invalid_host');
  });
});
