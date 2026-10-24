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
});
