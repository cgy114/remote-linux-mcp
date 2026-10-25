import { describe, expect, it, vi } from 'vitest';
import type { TransferDeps } from '../../../src/transfer/deps.js';

const state = vi.hoisted(() => ({
  sshInputs: [] as Record<string, unknown>[],
  sftpInputs: [] as Record<string, unknown>[],
  run: (): Record<string, unknown> => ({
    argv: [],
    displayCommand: 'cmd',
    exitCode: 0,
    signal: null,
    stdout: '',
    stderr: '',
    stdoutBytes: 0,
    stderrBytes: 0,
    stdoutTruncated: false,
    stderrTruncated: false,
    timedOut: false,
    durationMs: 1,
  }),
}));

vi.mock('../../../src/pipeline/run-command.js', () => ({
  runSshCommand: async (input: Record<string, unknown>) => {
    state.sshInputs.push(input);
    return state.run();
  },
}));

vi.mock('../../../src/ssh/runner.js', () => ({
  runSftp: async (input: Record<string, unknown>) => {
    state.sftpInputs.push(input);
    return state.run();
  },
}));

const { remainingMs, runRemoteCommand, runSftpSteps } = await import(
  '../../../src/transfer/deps.js'
);

function makeDeps(overrides: Partial<TransferDeps> = {}): TransferDeps {
  return {
    target: {
      config: { defaults: { maxOutputBytes: 123456 } },
      host: {
        alias: 'web1',
        host: '10.0.0.5',
        user: 'deploy',
        port: 22,
        cwd: '~',
        timeouts: { connectMs: 5000, commandMs: 15000, checkMs: 8000 },
        maxOutputBytes: 1048576,
        sudo: { mode: 'off', allow: [], deny: [] },
      },
      destination: 'deploy@10.0.0.5:22',
    },
    knownHostsFile: 'C:\\cfg\\known_hosts',
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn(), child: vi.fn() },
    limits: { maxFileBytes: 10, maxFiles: 10, maxTotalBytes: 100, maxDepth: 5 },
    deadlineMs: Date.now() + 100_000,
    ...overrides,
  } as unknown as TransferDeps;
}

describe('transfer deps', () => {
  it('computes remaining time with a zero floor', () => {
    expect(remainingMs(makeDeps({ deadlineMs: Date.now() + 5000 }))).toBeGreaterThan(4000);
    expect(remainingMs(makeDeps({ deadlineMs: Date.now() - 1 }))).toBe(0);
  });

  it('uses min(requested, remaining) and defaults', async () => {
    state.sshInputs.length = 0;
    const deps = makeDeps();
    await runRemoteCommand(deps, 'echo hi');
    const input = state.sshInputs[0]!;
    expect(input['remoteCommand']).toBe('echo hi');
    expect(input['timeoutMs']).toBe(15000);
    expect(input['maxOutputBytes']).toBe(123456);
    expect(input['knownHostsFile']).toBe('C:\\cfg\\known_hosts');
    expect(input['mode']).toBe('strict');
    expect(input['label']).toBe('transfer:web1');
  });

  it('caps the timeout by the deadline', async () => {
    state.sshInputs.length = 0;
    const deps = makeDeps({ deadlineMs: Date.now() + 1000 });
    await runRemoteCommand(deps, 'x', { timeoutMs: 99_999 });
    const timeout = state.sshInputs[0]!['timeoutMs'] as number;
    expect(timeout).toBeLessThanOrEqual(1000);
    expect(timeout).toBeGreaterThan(0);
  });

  it('passes streaming options through', async () => {
    state.sshInputs.length = 0;
    await runRemoteCommand(makeDeps(), 'x', {
      stdinFile: 'in.bin',
      stdoutFile: 'out.bin',
      label: 'custom',
    });
    expect(state.sshInputs[0]).toMatchObject({
      stdinFile: 'in.bin',
      stdoutFile: 'out.bin',
      label: 'custom',
    });
  });

  it('runs sftp batches through buildSftpArgv with stdin text', async () => {
    state.sftpInputs.length = 0;
    await runSftpSteps(makeDeps(), ['put "/a" "/b"', 'rename "/b" "/c"'], {
      extra: ['-l', '4096'],
    });
    const input = state.sftpInputs[0]!;
    expect(input['stdinData']).toBe('put "/a" "/b"\nrename "/b" "/c"\n');
    expect(input['timeoutMs']).toBe(15000);
    expect(input['label']).toBe('sftp:web1');
    const argv = input['argv'] as string[];
    expect(argv).toContain('-b');
    expect(argv).toContain('-q');
    expect(argv).toContain('-l');
    expect(argv.at(-1)).toBe('deploy@10.0.0.5');
  });

  it('uses empty stdin for an empty batch', async () => {
    state.sftpInputs.length = 0;
    await runSftpSteps(makeDeps(), []);
    expect(state.sftpInputs[0]!['stdinData']).toBe('');
  });

  it('runs through the control channel when deps.control is present', async () => {
    state.sshInputs.length = 0;
    const calls: Array<{ command: string; opts: Record<string, unknown> }> = [];
    const deps = makeDeps({
      deadlineMs: Date.now() + 5000,
      control: {
        run: async (command: string, opts: Record<string, unknown>) => {
          calls.push({ command, opts });
          return { exitCode: 3, stdout: 'hello', timedOut: false, durationMs: 7 };
        },
      },
    });

    const run = await runRemoteCommand(deps, 'probe thing', { timeoutMs: 99_999 });

    expect(calls).toHaveLength(1);
    expect(calls[0]!.command).toBe('probe thing');
    // timeout 仍取 min(requested, remaining) 与 commandMs 的较小值。
    expect(calls[0]!.opts['maxOutputBytes']).toBe(123456);
    expect(calls[0]!.opts['timeoutMs']).toBeLessThanOrEqual(15000);
    expect(calls[0]!.opts['timeoutMs']).toBeGreaterThan(0);
    expect(run).toMatchObject({
      argv: [],
      displayCommand: 'probe thing',
      exitCode: 3,
      signal: null,
      stdout: 'hello',
      stderr: '',
      stdoutBytes: 5,
      stderrBytes: 0,
      stdoutTruncated: false,
      stderrTruncated: false,
      timedOut: false,
      durationMs: 7,
    });
    expect(state.sshInputs).toHaveLength(0);
  });

  it('maps control timeouts into RunResult without spawning ssh', async () => {
    state.sshInputs.length = 0;
    const deps = makeDeps({
      control: {
        run: async () => ({ exitCode: null, stdout: '', timedOut: true, durationMs: 42 }),
      },
    });

    const run = await runRemoteCommand(deps, 'sleep 9');
    expect(run.timedOut).toBe(true);
    expect(run.exitCode).toBeNull();
    expect(run.durationMs).toBe(42);
    expect(state.sshInputs).toHaveLength(0);
  });

  it('reports control-channel errors as an ssh transport failure without reconnecting', async () => {
    state.sshInputs.length = 0;
    const deps = makeDeps({
      control: {
        run: async () => {
          throw new Error('control session closed');
        },
      },
    });

    const run = await runRemoteCommand(deps, 'swap');
    // 与 one-shot ssh 的非零/传输失败保持同一分类路径。
    expect(run.exitCode).toBe(255);
    expect(run.stderr).toBe('control session closed');
    expect(run.stdout).toBe('');
    expect(run.spawnError).toBeUndefined();
    // 不在控制通道失败后回退到新连接，避免重复执行有副作用的命令。
    expect(state.sshInputs).toHaveLength(0);
  });

  it('keeps streaming commands on one-shot ssh even with a control channel', async () => {
    state.sshInputs.length = 0;
    const calls: string[] = [];
    const deps = makeDeps({
      control: {
        run: async (command: string) => {
          calls.push(command);
          return { exitCode: 0, stdout: '', timedOut: false, durationMs: 1 };
        },
      },
    });

    await runRemoteCommand(deps, 'tar -cf - .', { stdoutFile: 'archive.tar' });
    expect(calls).toHaveLength(0);
    expect(state.sshInputs).toHaveLength(1);
    expect(state.sshInputs[0]!['stdoutFile']).toBe('archive.tar');
  });
});
