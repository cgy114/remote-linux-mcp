import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { CallToolResult } from '@modelcontextprotocol/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resolvePaths } from '../../src/config/paths.js';
import { UsageError } from '../../src/errors/classes.js';
import { runSshOperation, type AuditDeniedArgs } from '../../src/pipeline/operation.js';
import type { ToolContext } from '../../src/tools/common.js';
import type { Defaults, FilesConfig, Logger, MCPPaths, RemoteConfig } from '../../src/types.js';

const KEY_BLOB = Buffer.from('remote-mcp-denied-host-key').toString('base64');
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

describe('pipeline auditDenied', () => {
  let root: string;
  let paths: MCPPaths;
  let log: Logger;

  function makeConfig(): RemoteConfig {
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
      hosts: { web1: { host: '10.0.0.5', user: 'deploy' } },
      files: FILES,
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
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-denied-'));
    paths = resolvePaths({ explicit: path.join(root, 'config.yaml'), env: {}, homeDir: root });
    log = makeLogger();
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  function hooks(auditDenied: (args: AuditDeniedArgs) => void | Promise<void>) {
    return {
      input: {} as { host?: string },
      ctx: makeCtx(makeConfig()),
      prepare: async () => ({ ok: true }),
      execute: async (): Promise<{ value: number }> => ({ value: 1 }),
      auditDenied,
      format: (): CallToolResult => ({ content: [{ type: 'text', text: 'done' }] }),
    };
  }

  it('calls auditDenied on trust failure and preserves the HostKey result', async () => {
    const seen: AuditDeniedArgs[] = [];
    const result = await runSshOperation(hooks((args) => seen.push(args)));
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('HostKey');
    expect(seen).toHaveLength(1);
    expect(seen[0]!.phase).toBe('trust');
    expect(seen[0]!.error.kind).toBe('HostKey');
    expect(seen[0]!.target?.destination).toBe('deploy@10.0.0.5:22');
  });

  it('calls auditDenied on resolve failure without a target', async () => {
    const seen: AuditDeniedArgs[] = [];
    const result = await runSshOperation({ ...hooks((args) => seen.push(args)), input: { host: 'ghost' } });
    expect(result.isError).toBe(true);
    expect(seen).toHaveLength(1);
    expect(seen[0]!.phase).toBe('resolve');
    expect(seen[0]!.target).toBeUndefined();
    expect(seen[0]!.error.code).toBe('unknown_alias');
  });

  it('calls auditDenied on prepare failure', async () => {
    await installTrust();
    const seen: AuditDeniedArgs[] = [];
    const result = await runSshOperation({
      ...hooks((args) => seen.push(args)),
      prepare: () => {
        throw new UsageError('cannot prepare', { code: 'bad_prepare' });
      },
    });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('bad_prepare');
    expect(seen).toHaveLength(1);
    expect(seen[0]!.phase).toBe('prepare');
    expect(seen[0]!.error.code).toBe('bad_prepare');
  });

  it('swallows auditDenied exceptions and logs a warning', async () => {
    const result = await runSshOperation(
      hooks(() => {
        throw new Error('audit hook exploded');
      }),
    );
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('HostKey');
    expect(log.warn).toHaveBeenCalledWith(
      expect.objectContaining({ phase: 'trust' }),
      'auditDenied hook failed',
    );
  });

  it('does not call auditDenied for execute failures', async () => {
    await installTrust();
    const seen: AuditDeniedArgs[] = [];
    const result = await runSshOperation({
      ...hooks((args) => seen.push(args)),
      execute: async () => {
        throw new Error('boom');
      },
    });
    expect(result.isError).toBe(true);
    expect(seen).toEqual([]);
  });
});
