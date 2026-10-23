import { describe, expect, it, vi } from 'vitest';
import type { TransferDeps } from '../../../src/transfer/deps.js';

const state = vi.hoisted(() => {
  const make = (exitCode: number, stderr = ''): Record<string, unknown> => ({
    argv: [],
    displayCommand: 'cmd',
    exitCode,
    signal: null,
    stdout: '',
    stderr,
    stdoutBytes: 0,
    stderrBytes: 0,
    stdoutTruncated: false,
    stderrTruncated: false,
    timedOut: false,
    durationMs: 1,
  });
  return {
    commands: [] as string[],
    results: [] as Record<string, unknown>[],
    make,
    run: (exitCode: number, stderr = '') => {
      state.commands.push('');
      return make(exitCode, stderr);
    },
  };
});

vi.mock('../../../src/transfer/deps.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/transfer/deps.js')>();
  return {
    ...actual,
    runRemoteCommand: async (_deps: unknown, command: string) => {
      state.commands.push(command);
      return state.results.shift() ?? state.make(0);
    },
  };
});

const { createRemoteDirectory, newRemoteTempPath, removeRemoteTree, swapRemoteIntoPlace } =
  await import('../../../src/transfer/stage.js');

const deps = {
  target: { host: { alias: 'web1' } },
  ctx: {},
  limits: { maxFileBytes: 10, maxFiles: 10, maxTotalBytes: 100, maxDepth: 5 },
  deadlineMs: Date.now() + 10000,
} as unknown as TransferDeps;

describe('stage', () => {
  it('creates same-directory temp paths', () => {
    const p = newRemoteTempPath('/home/u/target');
    expect(p).toMatch(/^\/home\/u\/\.remote-mcp-tmp-[0-9a-f]{16}$/);
    expect(newRemoteTempPath('~/target')).toMatch(/^~\/\.remote-mcp-tmp-[0-9a-f]{16}$/);
  });

  it('creates directories and reports failures as facts', async () => {
    state.commands.length = 0;
    state.results = [state.make(0)];
    const ok = await createRemoteDirectory(deps, '/home/u/a b');
    expect(ok.ok).toBe(true);
    expect(state.commands[0]).toBe("mkdir -p -- '/home/u/a b'");

    state.results = [state.make(1, 'mkdir: cannot create')];
    const failed = await createRemoteDirectory(deps, '/home/u/x');
    expect(failed.ok).toBe(false);
    expect(failed.error).toMatchObject({ kind: 'RemoteExit', code: 'remote_exit' });
  });

  it('refuses to remove root or home', async () => {
    await expect(removeRemoteTree(deps, '/')).rejects.toMatchObject({ code: 'remote_path_invalid' });
    await expect(removeRemoteTree(deps, '~')).rejects.toMatchObject({ code: 'remote_path_invalid' });
    state.results = [state.make(0)];
    const ok = await removeRemoteTree(deps, '/home/u/tmp');
    expect(ok.ok).toBe(true);
    expect(state.commands.at(-1)).toBe("rm -rf -- '/home/u/tmp'");
  });

  describe('swapRemoteIntoPlace', () => {
    it('moves target to backup then staged into place', async () => {
      state.commands.length = 0;
      state.results = [state.make(0), state.make(0)];
      const result = await swapRemoteIntoPlace(deps, {
        staged: '/home/u/.tmp',
        target: '/home/u/target',
      });
      expect(result.ok).toBe(true);
      expect(result.rolledBack).toBe(false);
      expect(result.backup).toMatch(/^\/home\/u\/\.remote-mcp-tmp-/);
      expect(state.commands[0]).toContain("mv -f -- '/home/u/target'");
      expect(state.commands[1]).toBe("mv -f -- '/home/u/.tmp' '/home/u/target'");
    });

    it('rolls back when the commit fails', async () => {
      state.commands.length = 0;
      state.results = [state.make(0), state.make(1, 'rename failed'), state.make(0)];
      const result = await swapRemoteIntoPlace(deps, {
        staged: '/a/.tmp',
        target: '/a/target',
        backup: '/a/.backup',
      });
      expect(result.ok).toBe(false);
      expect(result.rolledBack).toBe(true);
      expect(result.error?.code).toBe('remote_exit');
      expect(state.commands).toHaveLength(3);
      expect(state.commands[2]).toContain("mv -f -- '/a/.backup' '/a/target'");
    });

    it('reports a failed rollback', async () => {
      state.commands.length = 0;
      state.results = [state.make(0), state.make(1), state.make(1)];
      const result = await swapRemoteIntoPlace(deps, {
        staged: '/a/.tmp',
        target: '/a/target',
        backup: '/a/.backup',
      });
      expect(result.ok).toBe(false);
      expect(result.rolledBack).toBe(false);
    });

    it('does not commit when backing up fails', async () => {
      state.commands.length = 0;
      state.results = [state.make(1, 'mv failed')];
      const result = await swapRemoteIntoPlace(deps, {
        staged: '/a/.tmp',
        target: '/a/target',
      });
      expect(result.ok).toBe(false);
      expect(result.rolledBack).toBe(false);
      expect(state.commands).toHaveLength(1);
    });

    it('rejects roots and identical paths', async () => {
      await expect(
        swapRemoteIntoPlace(deps, { staged: '/a/.tmp', target: '/' }),
      ).rejects.toMatchObject({ code: 'remote_path_invalid' });
      await expect(
        swapRemoteIntoPlace(deps, { staged: '/a/same', target: '/a/same' }),
      ).rejects.toMatchObject({ code: 'remote_path_invalid' });
      await expect(
        swapRemoteIntoPlace(deps, {
          staged: '/a/.tmp',
          target: '/a/target',
          backup: '/a/.tmp',
        }),
      ).rejects.toMatchObject({ code: 'remote_path_invalid' });
    });
  });
});
