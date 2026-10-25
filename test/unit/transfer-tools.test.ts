import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ResolvedTarget } from '../../src/pipeline/target.js';
import { buildTransferAuditRecord } from '../../src/audit/transfer-audit.js';
import type { ToolContext } from '../../src/tools/common.js';
import type { RemoteConfig, ToolError } from '../../src/types.js';

const state = vi.hoisted(() => {
  const mkTransfer = (overrides: Record<string, unknown> = {}) => ({
    ok: true,
    direction: 'upload',
    kind: 'file',
    sourcePath: '/local/a.txt',
    targetPath: '/remote/a.txt',
    files: 1,
    bytes: 5,
    sha256: 'a'.repeat(64),
    verified: true,
    atomicReplace: true,
    overwritten: false,
    durationMs: 1,
    ...overrides,
  });
  return {
    trust: { ok: true } as Record<string, unknown>,
    calls: [] as string[],
    uploadFacts: () => mkTransfer(),
    downloadFacts: () => mkTransfer({ direction: 'download' }),
    readFacts: () => ({
      ok: true,
      path: '/home/u/a.txt',
      size: 5,
      sha256: 'b'.repeat(64),
      mode: 0o644,
      encoding: 'utf8',
      content: Buffer.from('hello'),
      returnedBytes: 5,
      truncated: false,
      durationMs: 1,
    }),
    writeFacts: () =>
      mkTransfer({
        direction: undefined,
        kind: undefined,
        targetPath: '/remote/a.txt',
        mode: 0o644,
      }),
    mkTransfer,
    controlOpens: [] as Record<string, unknown>[],
    controlCloses: 0,
    controlHandle: undefined as unknown,
    lastDeps: undefined as unknown,
  };
});

vi.mock('../../src/pipeline/trust.js', () => ({
  checkTrust: async () => state.trust,
  trustFactToToolError: () => ({
    kind: 'HostKey',
    code: 'host_key',
    message: 'untrusted',
    retryable: false,
  }),
}));

vi.mock('../../src/transfer/single-file.js', () => ({
  uploadSingleFile: async (input: Record<string, unknown>) => {
    state.calls.push('uploadSingleFile');
    state.lastDeps = input['deps'];
    return state.uploadFacts();
  },
  downloadSingleFile: async (input: Record<string, unknown>) => {
    state.calls.push('downloadSingleFile');
    state.lastDeps = input['deps'];
    return state.downloadFacts();
  },
}));

vi.mock('../../src/transfer/directory.js', () => ({
  uploadTree: async (input: Record<string, unknown>) => {
    state.calls.push('uploadTree');
    state.lastDeps = input['deps'];
    return state.uploadFacts();
  },
  downloadTree: async (input: Record<string, unknown>) => {
    state.calls.push('downloadTree');
    state.lastDeps = input['deps'];
    return state.downloadFacts();
  },
}));

vi.mock('../../src/transfer/control.js', () => ({
  openTransferControl: async (opts: Record<string, unknown>) => {
    state.controlOpens.push(opts);
    return state.controlHandle;
  },
}));

vi.mock('../../src/transfer/remote-file.js', () => ({
  readRemoteFile: async () => {
    state.calls.push('readRemoteFile');
    return state.readFacts();
  },
  writeRemoteFile: async () => {
    state.calls.push('writeRemoteFile');
    return state.writeFacts();
  },
}));

const { buildUploadPlan, sshUpload, sshUploadInput } = await import(
  '../../src/tools/ssh-upload.js'
);
const { buildDownloadPlan, sshDownload, sshDownloadInput } = await import(
  '../../src/tools/ssh-download.js'
);
const { buildReadPlan, sshReadFile, sshReadFileInput } = await import(
  '../../src/tools/ssh-read-file.js'
);
const { buildWritePlan, sshWriteFile, sshWriteFileInput, decodeContent, parseModeInput } =
  await import('../../src/tools/ssh-write-file.js');
const { formatReadFileResult, formatTransferResult, formatWriteFileResult } = await import(
  '../../src/tools/transfer-format.js'
);

let base: string;
let root: string;
let outsideRoot: string;

beforeAll(async () => {
  base = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-tools-'));
  root = path.join(base, 'root');
  outsideRoot = path.join(base, 'outside');
  await fs.mkdir(root);
  await fs.mkdir(outsideRoot);
  await fs.writeFile(path.join(root, 'a.txt'), 'hello');
  await fs.writeFile(path.join(root, 'exists.txt'), 'old');
  await fs.writeFile(path.join(outsideRoot, 'secret.txt'), 'nope');
  await fs.mkdir(path.join(root, 'tree'));
  await fs.writeFile(path.join(root, 'tree', 'inside.txt'), 'hi');
});

afterAll(async () => {
  await fs.rm(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
});

let configDir: string;
let ctx: ToolContext;
let config: RemoteConfig;

function makeConfig(localRoots: string[] = [root], remoteDeny: string[] = []): RemoteConfig {
  const files = {
    localRoots,
    remoteDeny,
    maxFileBytes: 1000,
    maxFiles: 100,
    maxTotalBytes: 10_000,
    maxDepth: 10,
    transferTimeoutMs: 30_000,
  };
  return {
    version: 1,
    sourcePath: path.join(base, 'config.yaml'),
    baseDir: base,
    defaults: {
      port: 22,
      defaultCwd: '~',
      timeouts: { connectMs: 5000, commandMs: 15000, checkMs: 8000 },
      maxOutputBytes: 1048576,
      sudo: { mode: 'off', allow: [], deny: [] },
      files,
    },
    security: { hostKeyPolicy: 'pinned' },
    hosts: { web1: { host: '127.0.0.1', user: 'u' } },
    files,
  };
}

function makeTarget(cfg: RemoteConfig = config): ResolvedTarget {
  return {
    config: cfg,
    host: {
      alias: 'web1',
      host: '127.0.0.1',
      user: 'u',
      port: 22,
      cwd: '~',
      timeouts: { connectMs: 5000, commandMs: 15000, checkMs: 8000 },
      maxOutputBytes: 1048576,
      sudo: { mode: 'off', allow: [], deny: [] },
    },
    destination: 'u@127.0.0.1:22',
  };
}

async function makeCtx(): Promise<ToolContext> {
  configDir = await fs.mkdtemp(path.join(base, 'cfg-'));
  return {
    paths: {
      configFile: path.join(configDir, 'config.yaml'),
      configDir,
      knownHostsFile: path.join(configDir, 'known_hosts'),
      trustRegistryFile: path.join(configDir, 'trusted.json'),
      trustLockFile: path.join(configDir, '.trust.lock'),
      source: 'flag',
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn(), child: vi.fn() },
    getConfig: async () => config,
  };
}

async function auditLines(): Promise<Record<string, unknown>[]> {
  const file = path.join(configDir, 'audit.jsonl');
  const text = await fs.readFile(file, 'utf8');
  return text
    .split(/\r?\n/)
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

function reset(): void {
  state.trust = { ok: true };
  state.calls.length = 0;
  state.uploadFacts = () => state.mkTransfer();
  state.downloadFacts = () => state.mkTransfer({ direction: 'download' });
  state.readFacts = () => ({
    ok: true,
    path: '/home/u/a.txt',
    size: 5,
    sha256: 'b'.repeat(64),
    mode: 0o644,
    encoding: 'utf8',
    content: Buffer.from('hello'),
    returnedBytes: 5,
    truncated: false,
    durationMs: 1,
  });
  state.writeFacts = () =>
    state.mkTransfer({
      direction: undefined,
      kind: undefined,
      targetPath: '/remote/a.txt',
      mode: 0o644,
    });
  state.controlOpens.length = 0;
  state.controlCloses = 0;
  state.lastDeps = undefined;
  state.controlHandle = {
    sessionId: 'sess_ctrl',
    run: async () => ({ exitCode: 0, stdout: '', timedOut: false, durationMs: 1 }),
    close: async () => {
      state.controlCloses += 1;
    },
  };
}

beforeEach(async () => {
  reset();
  config = makeConfig();
  ctx = await makeCtx();
});

describe('transfer tool schemas', () => {
  it('accepts minimal upload/download inputs and rejects unknown keys', () => {
    expect(sshUploadInput.parse({ local_path: '/a', remote_path: '/b' })).toEqual({
      local_path: '/a',
      remote_path: '/b',
    });
    expect(() =>
      sshUploadInput.parse({ local_path: '/a', remote_path: '/b', unexpected: true }),
    ).toThrow();
    expect(
      sshDownloadInput.parse({ remote_path: '/b', local_path: '/a', recursive: true }),
    ).toMatchObject({ recursive: true });
  });

  it('bounds read_file inputs', () => {
    expect(sshReadFileInput.parse({ path: '~/a' })).toEqual({ path: '~/a' });
    expect(() => sshReadFileInput.parse({ path: '~/a', max_bytes: 9 * 1024 * 1024 })).toThrow();
    expect(() => sshReadFileInput.parse({ path: '~/a', tail_lines: 0 })).toThrow();
  });

  it('accepts octal mode strings and rejects invalid encodings', () => {
    expect(sshWriteFileInput.parse({ path: '~/a', content: 'x', mode: '0640' })).toMatchObject({
      mode: '0640',
    });
    expect(sshWriteFileInput.parse({ path: '~/a', content: 'x', mode: 420 })).toMatchObject({
      mode: 420,
    });
    expect(() =>
      sshWriteFileInput.parse({ path: '~/a', content: 'x', encoding: 'hex' }),
    ).toThrow();
    expect(parseModeInput('0640')).toBe(0o640);
    expect(parseModeInput('7777')).toBe(0o777);
    expect(() => parseModeInput('0999')).toThrow();
  });

  it('decodes utf8/base64 strictly', () => {
    expect(decodeContent('aGVsbG8=', 'base64').toString('utf8')).toBe('hello');
    expect(() => decodeContent('!!!', 'base64')).toThrow(
      expect.objectContaining({ code: 'content_invalid_base64' }),
    );
    expect(() => decodeContent('\ud800', 'utf8')).toThrow(
      expect.objectContaining({ code: 'content_invalid_utf8' }),
    );
  });
});

describe('prepare plans', () => {
  it('builds a file upload plan inside local_roots', async () => {
    const plan = await buildUploadPlan(
      { local_path: path.join(root, 'a.txt'), remote_path: '~/a.txt' },
      makeTarget(),
    );
    expect(plan.kind).toBe('file');
    expect(plan.manifest).toEqual([]);
    expect(plan.remote).toBe('~/a.txt');
  });

  it('builds a directory manifest for recursive uploads', async () => {
    const plan = await buildUploadPlan(
      {
        local_path: path.join(root, 'tree'),
        remote_path: '~/tree',
        recursive: true,
      },
      makeTarget(),
    );
    expect(plan.kind).toBe('directory');
    expect(plan.manifest).toEqual([
      expect.objectContaining({ path: 'inside.txt', type: 'file', size: 2 }),
    ]);
  });

  it('rejects uploads outside local_roots with local_root_not_allowed', async () => {
    await expect(
      buildUploadPlan(
        { local_path: path.join(outsideRoot, 'secret.txt'), remote_path: '~/x' },
        makeTarget(),
      ),
    ).rejects.toMatchObject({ code: 'local_root_not_allowed' });
  });

  it('rejects remote write deny paths and disabled transfers', async () => {
    await expect(
      buildUploadPlan(
        { local_path: path.join(root, 'a.txt'), remote_path: '/etc/passwd' },
        makeTarget(),
      ),
    ).rejects.toMatchObject({ code: 'remote_denied_write' });

    await expect(
      buildUploadPlan(
        { local_path: path.join(root, 'a.txt'), remote_path: '~/a.txt' },
        makeTarget(makeConfig([])),
      ),
    ).rejects.toMatchObject({ code: 'transfer_disabled' });
  });

  it('gates local download targets', async () => {
    const plan = await buildDownloadPlan(
      { remote_path: '~/a.txt', local_path: path.join(root, 'new.txt') },
      makeTarget(),
    );
    expect(plan.localTarget.exists).toBe(false);

    await expect(
      buildDownloadPlan(
        {
          remote_path: '~/a.txt',
          local_path: path.join(root, 'exists.txt'),
          overwrite: false,
        },
        makeTarget(),
      ),
    ).rejects.toMatchObject({ code: 'target_exists' });

    await expect(
      buildDownloadPlan(
        { remote_path: '~/a.txt', local_path: path.join(outsideRoot, 'x') },
        makeTarget(),
      ),
    ).rejects.toMatchObject({ code: 'local_root_not_allowed' });

    await expect(
      buildDownloadPlan(
        { remote_path: '~/.ssh/id_ed25519', local_path: path.join(root, 'x') },
        makeTarget(),
      ),
    ).rejects.toMatchObject({ code: 'remote_denied_read' });
  });

  it('clamps read max_bytes and enforces read deny', () => {
    const plan = buildReadPlan({ path: '~/a.txt', max_bytes: 5000 }, makeTarget());
    expect(plan.maxBytes).toBe(1000);
    expect(() => buildReadPlan({ path: '~/.ssh/id_ed25519' }, makeTarget())).toThrow(
      expect.objectContaining({ code: 'remote_denied_read' }),
    );
  });

  it('decodes and limits write content before any spawn', () => {
    const plan = buildWritePlan(
      { path: '~/a.txt', content: 'aGVsbG8=', encoding: 'base64', mode: '0600' },
      makeTarget(),
    );
    expect(plan.content.toString('utf8')).toBe('hello');
    expect(plan.mode).toBe(0o600);

    expect(() =>
      buildWritePlan({ path: '~/a.txt', content: 'x'.repeat(2000) }, makeTarget()),
    ).toThrow(expect.objectContaining({ code: 'file_too_large' }));
    expect(() =>
      buildWritePlan({ path: '/etc/passwd', content: 'x' }, makeTarget()),
    ).toThrow(expect.objectContaining({ code: 'remote_denied_write' }));
  });
});

describe('tool wiring: audit and formatting', () => {
  it('writes exactly one audit record per successful call', async () => {
    const result = await sshUpload(
      { host: 'web1', local_path: path.join(root, 'a.txt'), remote_path: '~/a.txt' },
      ctx,
    );
    expect(result.isError).not.toBe(true);
    expect(state.calls).toEqual(['uploadSingleFile']);

    const lines = await auditLines();
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatchObject({
      tool: 'ssh_upload',
      alias: 'web1',
      direction: 'upload',
      outcome: 'verified',
      queue_ms: 0,
      files: 1,
      bytes: 5,
    });
  });

  it('opens and closes one internal control channel per file/directory transfer', async () => {
    const up = await sshUpload(
      { host: 'web1', local_path: path.join(root, 'a.txt'), remote_path: '~/a.txt' },
      ctx,
    );
    expect(up.isError).not.toBe(true);
    expect(state.controlOpens).toHaveLength(1);
    expect(state.controlOpens[0]).toMatchObject({
      cwd: '~',
      knownHostsFile: ctx.paths.knownHostsFile,
    });
    expect((state.lastDeps as { control?: unknown }).control).toBe(state.controlHandle);
    expect(state.controlCloses).toBe(1);

    const tree = await sshUpload(
      {
        host: 'web1',
        local_path: path.join(root, 'tree'),
        remote_path: '~/tree',
        recursive: true,
      },
      ctx,
    );
    expect(tree.isError).not.toBe(true);
    expect(state.controlOpens).toHaveLength(2);
    expect((state.lastDeps as { control?: unknown }).control).toBe(state.controlHandle);
    expect(state.controlCloses).toBe(2);

    const down = await sshDownload(
      { host: 'web1', remote_path: '~/a.txt', local_path: path.join(root, 'control-dl.txt') },
      ctx,
    );
    expect(down.isError).not.toBe(true);
    expect(state.controlOpens).toHaveLength(3);
    expect((state.lastDeps as { control?: unknown }).control).toBe(state.controlHandle);
    expect(state.controlCloses).toBe(3);
  });

  it('falls back to one-shot transfer when the control session is unavailable', async () => {
    state.controlHandle = undefined;
    const result = await sshUpload(
      { host: 'web1', local_path: path.join(root, 'a.txt'), remote_path: '~/a.txt' },
      ctx,
    );
    expect(result.isError).not.toBe(true);
    expect((state.lastDeps as { control?: unknown }).control).toBeUndefined();
    expect(state.controlCloses).toBe(0);
  });

  it('records denied calls without spawning and without content', async () => {
    state.trust = { ok: false, fact: { reason: 'not_registered' } };
    const marker = 'TOP_SECRET_MARKER_123';
    const result = await sshWriteFile(
      { host: 'web1', path: '~/a.txt', content: marker },
      ctx,
    );
    expect(result.isError).toBe(true);
    expect(state.calls).toEqual([]);

    const lines = await auditLines();
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatchObject({
      tool: 'ssh_write_file',
      outcome: 'denied',
      queue_ms: 0,
      failureKind: 'HostKey',
    });
    const raw = await fs.readFile(path.join(configDir, 'audit.jsonl'), 'utf8');
    expect(raw).not.toContain(marker);
  });

  it('marks write_file success audit without embedding content', async () => {
    const marker = 'WRITE_CONTENT_MARKER_456';
    const result = await sshWriteFile(
      { host: 'web1', path: '~/a.txt', content: marker },
      ctx,
    );
    expect(result.isError).not.toBe(true);
    const raw = await fs.readFile(path.join(configDir, 'audit.jsonl'), 'utf8');
    expect(raw).not.toContain(marker);
    const lines = await auditLines();
    expect(lines[0]).toMatchObject({ tool: 'ssh_write_file', outcome: 'verified', queue_ms: 0 });
  });

  it('returns read_file content in structuredContent', async () => {
    const result = await sshReadFile({ host: 'web1', path: '~/a.txt' }, ctx);
    expect(result.isError).not.toBe(true);
    const structured = result.structuredContent as Record<string, unknown>;
    expect(structured['encoding']).toBe('utf8');
    expect(structured['content']).toBe('hello');
    expect(structured['returned_bytes']).toBe(5);
    expect(structured['truncated']).toBe(false);
  });

  it('formats failures with isError and an error object including retryable', () => {
    const failure: ToolError = {
      kind: 'Policy',
      code: 'target_exists',
      message: 'already exists',
      hint: 'pass overwrite=true',
      retryable: false,
    };
    const result = formatTransferResult({
      tool: 'ssh_upload',
      host: 'web1',
      facts: state.mkTransfer({ ok: false, failure }),
    });
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({
      error: {
        kind: 'Policy',
        code: 'target_exists',
        message: 'already exists',
        hint: 'pass overwrite=true',
        retryable: false,
      },
    });
  });

  it('keeps the structured key set identical across denial and execution failure', async () => {
    const input = {
      host: 'web1',
      local_path: path.join(root, 'a.txt'),
      remote_path: '~/a.txt',
    };

    // 执行失败（runSshOperation 已通过信任/准备，format 阶段返回 facts.failure）。
    state.uploadFacts = () =>
      state.mkTransfer({
        ok: false,
        failure: {
          kind: 'Policy',
          code: 'target_exists',
          message: 'exists',
          retryable: false,
        },
      });
    const executed = await sshUpload(input, ctx);

    // trust 拒绝（租约前）。
    state.uploadFacts = () => state.mkTransfer();
    state.trust = { ok: false, fact: { reason: 'not_registered' } };
    const denied = await sshUpload(input, ctx);

    // prepare 拒绝（租约前）。
    state.trust = { ok: true };
    const prepared = await sshUpload(
      { host: 'web1', local_path: path.join(root, 'a.txt'), remote_path: '/etc/passwd' },
      ctx,
    );

    for (const result of [denied, prepared, executed]) {
      expect(result.isError).toBe(true);
      const structured = result.structuredContent as Record<string, unknown>;
      expect(Object.keys(structured).sort()).toEqual(['error', 'host', 'tool']);
      expect(structured['tool']).toBe('ssh_upload');
      expect(structured['host']).toBe('web1');
      expect((structured['error'] as Record<string, unknown>)['retryable']).toBeTypeOf('boolean');
    }
  });

  it('formats read/write/transfer success payloads', () => {
    const transfer = formatTransferResult({
      tool: 'ssh_upload',
      host: 'web1',
      facts: state.mkTransfer(),
      queueMs: 3,
    });
    expect(transfer.isError).not.toBe(true);
    expect(transfer.structuredContent).toMatchObject({
      file_count: 1,
      bytes: 5,
      atomic_replace: true,
      verified: true,
      queue_ms: 3,
    });

    const read = formatReadFileResult({
      host: 'web1',
      facts: state.readFacts() as never,
    });
    expect((read.structuredContent as Record<string, unknown>)['content']).toBe('hello');

    const write = formatWriteFileResult({
      host: 'web1',
      facts: state.writeFacts() as never,
    });
    expect(write.structuredContent).toMatchObject({
      mode: 0o644,
      atomic_replace: true,
      verified: true,
    });
  });

  it('formats state-machine failures from tools', async () => {
    state.uploadFacts = () =>
      state.mkTransfer({
        ok: false,
        failure: {
          kind: 'Policy',
          code: 'local_root_not_allowed',
          message: 'denied',
          retryable: false,
        },
      });
    const result = await sshUpload(
      { host: 'web1', local_path: path.join(root, 'a.txt'), remote_path: '~/a.txt' },
      ctx,
    );
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({ error: { code: 'local_root_not_allowed' } });
  });
});

describe('audit record derivation', () => {
  it('treats policy failures as denied', () => {
    const record = buildTransferAuditRecord({
      direction: 'upload',
      failure: { kind: 'Policy', code: 'target_exists' },
      files: 0,
      bytes: 0,
    });
    expect(record.outcome).toBe('denied');
  });

  it('treats verify failures as verify_failed', () => {
    const record = buildTransferAuditRecord({
      direction: 'download',
      failure: { kind: 'RemoteExit', code: 'verify_sha256_mismatch' },
      files: 1,
      bytes: 5,
    });
    expect(record.outcome).toBe('verify_failed');
  });
});
