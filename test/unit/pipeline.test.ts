import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { CallToolResult } from '@modelcontextprotocol/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resolvePaths } from '../../src/config/paths.js';
import { withHostLease } from '../../src/pipeline/lease.js';
import { runSshOperation } from '../../src/pipeline/operation.js';
import { resolveTarget } from '../../src/pipeline/target.js';
import { checkTrust, trustFactToToolError } from '../../src/pipeline/trust.js';
import type { HostLimiter } from '../../src/ssh/host-limiter.js';
import type { ToolContext } from '../../src/tools/common.js';
import type { Defaults, FilesConfig, Logger, MCPPaths, RemoteConfig } from '../../src/types.js';

const KEY_BLOB = Buffer.from('remote-mcp-pipeline-host-key').toString('base64');
const FINGERPRINT = `SHA256:${createHash('sha256')
  .update(Buffer.from(KEY_BLOB, 'base64'))
  .digest('base64')
  .replace(/=+$/, '')}`;

const FILES: FilesConfig = {
  localRoots: [],
  remoteDeny: [],
  maxFileBytes: 512 * 1024 * 1024,
  maxFiles: 10_000,
  maxTotalBytes: 4 * 1024 * 1024 * 1024,
  maxDepth: 64,
  transferTimeoutMs: 300_000,
};

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

function textOf(result: CallToolResult): string {
  const first = result.content[0] as { type: string; text?: string } | undefined;
  return first?.text ?? '';
}

function okResult(text: string): CallToolResult {
  return { content: [{ type: 'text', text }] };
}

function recordingLimiter(events: string[]): HostLimiter {
  return {
    async acquire(key: string) {
      events.push(`acquire:${key}`);
      return {
        queueMs: 3,
        release: () => {
          events.push(`release:${key}`);
        },
      };
    },
  };
}

describe('pipeline', () => {
  let root: string;
  let paths: MCPPaths;
  let log: Logger;

  function makeConfig(overrides: Partial<RemoteConfig> = {}): RemoteConfig {
    const defaults: Defaults = {
      port: 22,
      defaultCwd: '~',
      defaultHost: 'web1',
      timeouts: { connectMs: 5000, commandMs: 15000, checkMs: 8000 },
      maxOutputBytes: 1_048_576,
      sudo: { mode: 'off', allow: [], deny: [] },
      files: FILES,
    };
    return {
      version: 1,
      sourcePath: path.join(root, 'config.yaml'),
      baseDir: root,
      defaults,
      security: { hostKeyPolicy: 'pinned' },
      hosts: {
        web1: { host: '10.0.0.5', user: 'deploy' },
        web2: { host: '10.0.0.6', user: 'deploy' },
      },
      files: FILES,
      ...overrides,
    };
  }

  function makeCtx(config: RemoteConfig): ToolContext {
    return { paths, log, getConfig: async () => config };
  }

  async function installTrust(): Promise<void> {
    await fs.writeFile(
      paths.trustRegistryFile,
      JSON.stringify({
        version: 1,
        hosts: {
          web1: {
            algorithm: 'ssh-ed25519',
            keyBlob: KEY_BLOB,
            fingerprint: FINGERPRINT,
            firstSeenAt: '2026-10-01T00:00:00Z',
            lastVerifiedAt: '2026-10-01T00:00:00Z',
          },
        },
      }),
      'utf8',
    );
    await fs.writeFile(paths.knownHostsFile, `10.0.0.5 ssh-ed25519 ${KEY_BLOB}\n`, 'utf8');
  }

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-pipeline-'));
    paths = resolvePaths({ explicit: path.join(root, 'config.yaml'), env: {}, homeDir: root });
    log = makeLogger();
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  describe('resolveTarget', () => {
    it('uses defaults.default_host when host is omitted', async () => {
      const target = await resolveTarget({}, makeCtx(makeConfig()));
      expect(target.host.alias).toBe('web1');
      expect(target.destination).toBe('deploy@10.0.0.5:22');
    });

    it('prefers an explicit host', async () => {
      const target = await resolveTarget({ host: 'web2' }, makeCtx(makeConfig()));
      expect(target.host.alias).toBe('web2');
      expect(target.destination).toBe('deploy@10.0.0.6:22');
    });

    it('throws missing_host when neither host nor default_host is set', async () => {
      const config = makeConfig();
      config.defaults = { ...config.defaults, defaultHost: undefined };
      await expect(resolveTarget({}, makeCtx(config))).rejects.toMatchObject({ code: 'missing_host' });
    });

    it('throws unknown_alias for an alias absent from config', async () => {
      await expect(resolveTarget({ host: 'ghost' }, makeCtx(makeConfig()))).rejects.toMatchObject({
        code: 'unknown_alias',
      });
    });
  });

  describe('checkTrust / trustFactToToolError', () => {
    it('reports ok once the fingerprint is pinned and present in known_hosts', async () => {
      await installTrust();
      const config = makeConfig();
      const target = await resolveTarget({}, makeCtx(config));
      const trust = await checkTrust({
        alias: target.host.alias,
        host: target.host,
        paths,
        log,
      });
      expect(trust.ok).toBe(true);
    });

    it('maps a trust fact to HostKey and only carries reason/stderr', () => {
      const err = trustFactToToolError(
        { reason: 'not_registered', stderr: 'details here', exitCode: 255 },
        log,
      );
      expect(err.kind).toBe('HostKey');
      expect(err.hint).toContain('trust');
      expect(err.details?.['stderr']).toBe('details here');
      expect(err.details?.['exitCode']).toBeUndefined();
    });
  });

  describe('runSshOperation', () => {
    function hooks(config: RemoteConfig, events: string[], limiter: HostLimiter) {
      return {
        input: {} as { host?: string },
        ctx: makeCtx(config),
        limiter,
        prepare: () => {
          events.push('prepare');
          return { ok: true };
        },
        execute: async (): Promise<{ value: number }> => {
          events.push('execute');
          return { value: 1 };
        },
        classifyFailure: () => undefined,
        audit: () => {
          events.push('audit');
        },
        format: (): CallToolResult => {
          events.push('format');
          return okResult('done');
        },
      };
    }

    it('returns a HostKey error and never prepares/leases/executes when trust fails', async () => {
      const events: string[] = [];
      const limiter = recordingLimiter(events);
      const execute = vi.fn();
      const result = await runSshOperation<{ ok: boolean }, { value: number }>({
        ...hooks(makeConfig(), events, limiter),
        execute,
      });

      expect(result.isError).toBe(true);
      expect(textOf(result)).toContain('HostKey');
      expect(execute).not.toHaveBeenCalled();
      expect(events).toEqual([]);
    });

    it('labels pre-lease trust and prepare rejections with tool and host', async () => {
      const trustResult = await runSshOperation({
        ...hooks(makeConfig(), [], recordingLimiter([])),
        toolName: 'ssh_exec',
      });
      expect(trustResult.isError).toBe(true);
      expect(trustResult.structuredContent).toMatchObject({
        tool: 'ssh_exec',
        host: 'web1',
        error: { retryable: expect.any(Boolean) },
      });
      expect(Object.keys(trustResult.structuredContent as object).sort()).toEqual([
        'error',
        'host',
        'tool',
      ]);

      await installTrust();
      const prepareResult = await runSshOperation({
        ...hooks(makeConfig(), [], recordingLimiter([])),
        toolName: 'ssh_exec',
        prepare: () => {
          throw new Error('cannot prepare');
        },
      });
      expect(prepareResult.isError).toBe(true);
      expect(Object.keys(prepareResult.structuredContent as object).sort()).toEqual([
        'error',
        'host',
        'tool',
      ]);
      expect((prepareResult.structuredContent as { tool?: string }).tool).toBe('ssh_exec');
    });

    it('runs prepare -> lease -> execute -> audit -> format -> release', async () => {
      await installTrust();
      const events: string[] = [];
      const limiter = recordingLimiter(events);
      const result = await runSshOperation(hooks(makeConfig(), events, limiter));

      expect(result.isError).toBeUndefined();
      expect(textOf(result)).toBe('done');
      expect(events).toEqual([
        'prepare',
        'acquire:deploy@10.0.0.5:22',
        'execute',
        'audit',
        'format',
        'release:deploy@10.0.0.5:22',
      ]);
    });

    it('releases the lease when execute throws and converts the error to a result', async () => {
      await installTrust();
      const events: string[] = [];
      const limiter = recordingLimiter(events);
      const result = await runSshOperation({
        ...hooks(makeConfig(), events, limiter),
        execute: async (): Promise<{ value: number }> => {
          events.push('execute');
          throw new Error('boom');
        },
      });

      expect(result.isError).toBe(true);
      expect(events).toContain('acquire:deploy@10.0.0.5:22');
      expect(events.at(-1)).toBe('release:deploy@10.0.0.5:22');
    });

    it('captures a prepare failure before acquiring the lease and never rejects', async () => {
      await installTrust();
      const events: string[] = [];
      const limiter = recordingLimiter(events);
      const result = await runSshOperation({
        ...hooks(makeConfig(), events, limiter),
        prepare: () => {
          events.push('prepare');
          throw new Error('cannot prepare');
        },
      });

      expect(result.isError).toBe(true);
      expect(events).toEqual(['prepare']);
    });

    it('passes the classified failure to audit and format', async () => {
      await installTrust();
      const events: string[] = [];
      const limiter = recordingLimiter(events);
      const seen: Array<string | undefined> = [];
      const failure = { kind: 'Timeout' as const, code: 'timeout', message: 'slow', retryable: true };
      const result = await runSshOperation({
        ...hooks(makeConfig(), events, limiter),
        classifyFailure: () => failure,
        audit: ({ failure: f }) => {
          seen.push(f?.code);
        },
        format: ({ failure: f }): CallToolResult => {
          seen.push(f?.kind);
          return okResult('failed');
        },
      });

      expect(result.isError).toBeUndefined();
      expect(seen).toEqual(['timeout', 'Timeout']);
    });
  });

  describe('withHostLease', () => {
    it('returns the callback value and exposes queueMs', async () => {
      const events: string[] = [];
      const value = await withHostLease(
        'k',
        async (lease) => {
          events.push(`body:${lease.queueMs}`);
          return 42;
        },
        recordingLimiter(events),
      );
      expect(value).toBe(42);
      expect(events).toEqual(['acquire:k', 'body:3', 'release:k']);
    });

    it('releases when the callback throws', async () => {
      const events: string[] = [];
      await expect(
        withHostLease(
          'k',
          async () => {
            throw new Error('nope');
          },
          recordingLimiter(events),
        ),
      ).rejects.toThrow('nope');
      expect(events).toEqual(['acquire:k', 'release:k']);
    });
  });
});
