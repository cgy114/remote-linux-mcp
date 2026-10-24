import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../../../src/config/load.js';
import { resolvePaths } from '../../../src/config/paths.js';
import { configSchema, defaultsFor, filesFor } from '../../../src/config/schema.js';
import type { MCPPaths } from '../../../src/types.js';

const validHost = { host: '10.0.0.5', user: 'deploy' };
const base = (extra: Record<string, unknown> = {}) => ({
  version: 1,
  hosts: { web1: validHost },
  ...extra,
});

function ok(input: unknown): boolean {
  return configSchema.safeParse(input).success;
}

const DEFAULT_FILES = {
  localRoots: [],
  remoteDeny: [],
  maxFileBytes: 536870912,
  maxFiles: 10000,
  maxTotalBytes: 4294967296,
  maxDepth: 64,
  transferTimeoutMs: 300000,
};

describe('filesSchema', () => {
  it('accepts a fully specified files section', () => {
    expect(
      ok(
        base({
          files: {
            local_roots: ['~/.ssh', '/tmp/x'],
            remote_deny: ['/etc', '~/.gnupg'],
            max_file_bytes: 1024,
            max_files: 10,
            max_total_bytes: 2048,
            max_depth: 3,
            transfer_timeout_ms: 1000,
          },
        }),
      ),
    ).toBe(true);
  });

  it('rejects unknown fields inside files', () => {
    expect(ok(base({ files: { surprise: 1 } }))).toBe(false);
  });

  it('rejects the removed verify option (verification is a fixed policy)', () => {
    expect(ok(base({ files: { verify: 'manifest' } }))).toBe(false);
    expect(ok(base({ files: { verify: 'off' } }))).toBe(false);
  });

  it('rejects a non-positive transfer_timeout_ms and a negative max_depth', () => {
    expect(ok(base({ files: { transfer_timeout_ms: 0 } }))).toBe(false);
    expect(ok(base({ files: { max_depth: -1 } }))).toBe(false);
  });

  it('requires remote_deny entries to start with / or ~', () => {
    expect(ok(base({ files: { remote_deny: ['/etc'] } }))).toBe(true);
    expect(ok(base({ files: { remote_deny: ['~/.gnupg'] } }))).toBe(true);
    expect(ok(base({ files: { remote_deny: ['etc/passwd'] } }))).toBe(false);
  });

  it('rejects ".." segments and NUL bytes in remote_deny', () => {
    expect(ok(base({ files: { remote_deny: ['/a/../b'] } }))).toBe(false);
    expect(ok(base({ files: { remote_deny: ['/a' + String.fromCharCode(0) + 'b'] } }))).toBe(false);
  });

  it('enforces max_file_bytes <= max_total_bytes', () => {
    expect(ok(base({ files: { max_file_bytes: 2048, max_total_bytes: 1024 } }))).toBe(false);
    expect(ok(base({ files: { max_file_bytes: 1024, max_total_bytes: 1024 } }))).toBe(true);
    // 只给 max_total_bytes 时与默认 max_file_bytes（512 MiB）比较
    expect(ok(base({ files: { max_total_bytes: 1024 } }))).toBe(false);
  });
});

describe('filesFor / defaultsFor', () => {
  it('expands every default when files is absent', () => {
    const raw = configSchema.parse(base());
    expect(filesFor(raw)).toStrictEqual(DEFAULT_FILES);
  });

  it('keeps explicit values and resolves local_roots through the injected resolver', () => {
    const raw = configSchema.parse(
      base({
        files: {
          local_roots: ['rel/dir', '~/other'],
          remote_deny: ['/etc'],
          max_file_bytes: 1024,
          max_files: 5,
          max_total_bytes: 4096,
          max_depth: 2,
          transfer_timeout_ms: 5000,
        },
      }),
    );
    expect(filesFor(raw, (p) => `/abs/${p}`)).toStrictEqual({
      localRoots: ['/abs/rel/dir', '/abs/~/other'],
      remoteDeny: ['/etc'],
      maxFileBytes: 1024,
      maxFiles: 5,
      maxTotalBytes: 4096,
      maxDepth: 2,
      transferTimeoutMs: 5000,
    });
  });

  it('defaultsFor fills files and honors the resolver option', () => {
    const plain = configSchema.parse(base());
    expect(defaultsFor(plain).files).toStrictEqual(DEFAULT_FILES);

    const withRoots = configSchema.parse(base({ files: { local_roots: ['a'] } }));
    expect(defaultsFor(withRoots, { resolveLocalRoot: (p) => `/r/${p}` }).files.localRoots).toEqual([
      '/r/a',
    ]);
  });
});

describe('loadConfig files', () => {
  let root: string;
  let paths: MCPPaths;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-files-'));
    paths = resolvePaths({ explicit: path.join(root, 'config.yaml'), env: {}, homeDir: root });
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  it('resolves local_roots and exposes the same files object on cfg and defaults', async () => {
    await fs.writeFile(
      paths.configFile,
      `version: 1
files:
  local_roots: ["~/.ssh", "rel/dir"]
  remote_deny: ["/etc", "~/.gnupg"]
  max_file_bytes: 1048576
  max_files: 100
  max_total_bytes: 4194304
  max_depth: 8
  transfer_timeout_ms: 5000
hosts:
  a: { host: h, user: u }
`,
      'utf8',
    );

    const cfg = await loadConfig(paths);
    expect(cfg.files).toBe(cfg.defaults.files);
    expect(cfg.files.maxFileBytes).toBe(1048576);
    expect(cfg.files.maxFiles).toBe(100);
    expect(cfg.files.maxTotalBytes).toBe(4194304);
    expect(cfg.files.maxDepth).toBe(8);
    expect(cfg.files.transferTimeoutMs).toBe(5000);
    expect(cfg.files.remoteDeny).toEqual(['/etc', '~/.gnupg']);

    const [sshRoot, relRoot] = cfg.files.localRoots;
    expect(path.isAbsolute(sshRoot!)).toBe(true);
    expect(sshRoot!.endsWith(`${path.sep}.ssh`)).toBe(true);
    expect(relRoot).toBe(path.resolve(root, 'rel', 'dir'));
  });
});
