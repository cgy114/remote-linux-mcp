import { describe, expect, it } from 'vitest';
import { UsageError } from '../../../src/errors/classes.js';
import { DEFAULT_EXEC_LIMITS } from '../../../src/policy/remote-command.js';
import {
  buildSudoRemoteCommand,
  classifySudoRun,
  composeSudoStdin,
  isSudoCommand,
  stripLeadingSudoCommand,
} from '../../../src/policy/sudo.js';

function codeOf(fn: () => unknown): string | undefined {
  try {
    fn();
    return undefined;
  } catch (err) {
    expect(err).toBeInstanceOf(UsageError);
    return (err as UsageError).code;
  }
}

describe('buildSudoRemoteCommand', () => {
  it('builds a passwordless sudo wrapper around the inner bash script', () => {
    const plan = buildSudoRemoteCommand({
      command: 'id',
      mode: 'passwordless',
      limits: DEFAULT_EXEC_LIMITS,
    });
    expect(plan.sudoMode).toBe('passwordless');
    expect(plan.remoteCommand.startsWith('LC_ALL=C sudo -n -- /bin/bash -lc ')).toBe(true);
    expect(plan.remoteCommand).toContain('builtin cd -- "$HOME"');
    expect(plan.remoteCommand.endsWith("id'")).toBe(true);
    expect(plan.inner.cwd).toBe('~');
    expect(plan.inner.commandBytes).toBe(2);
  });

  it('builds a password-mode sudo wrapper with -S -k and an empty prompt', () => {
    const plan = buildSudoRemoteCommand({
      command: 'systemctl restart nginx',
      mode: 'password',
      limits: DEFAULT_EXEC_LIMITS,
      cwd: '/srv/app',
    });
    expect(plan.sudoMode).toBe('password');
    expect(plan.remoteCommand.startsWith("LC_ALL=C sudo -S -k -p '' -- /bin/bash -lc ")).toBe(true);
    expect(plan.inner.cwd).toBe('/srv/app');
  });

  it('escapes single quotes in the inner script', () => {
    const plan = buildSudoRemoteCommand({
      command: `echo 'x'`,
      mode: 'passwordless',
      limits: DEFAULT_EXEC_LIMITS,
    });
    expect(plan.remoteCommand).toContain(`'\\''`);
  });

  it('rejects invalid cwd and empty commands through buildExecCommand', () => {
    expect(
      codeOf(() =>
        buildSudoRemoteCommand({
          command: 'id',
          mode: 'passwordless',
          limits: DEFAULT_EXEC_LIMITS,
          cwd: 'relative',
        }),
      ),
    ).toBe('invalid_cwd');
    expect(
      codeOf(() =>
        buildSudoRemoteCommand({ command: '', mode: 'passwordless', limits: DEFAULT_EXEC_LIMITS }),
      ),
    ).toBe('invalid_command');
  });

  it('forces an English locale for sudo diagnostics in both modes', () => {
    for (const mode of ['passwordless', 'password'] as const) {
      const plan = buildSudoRemoteCommand({ command: 'id', mode, limits: DEFAULT_EXEC_LIMITS });
      expect(plan.remoteCommand.startsWith('LC_ALL=C sudo ')).toBe(true);
    }
  });

  it('enforces remote size limits', () => {
    expect(
      codeOf(() =>
        buildSudoRemoteCommand({
          command: 'id',
          mode: 'passwordless',
          limits: { maxRemoteUtf16: 50, maxRemoteUtf8: 50 },
        }),
      ),
    ).toBe('command_too_large');
  });
});

describe('composeSudoStdin', () => {
  it('appends the password newline and user stdin', () => {
    expect(composeSudoStdin(Buffer.from('pw'), Buffer.from('data')).toString()).toBe('pw\ndata');
  });

  it('adds only the newline when there is no user stdin', () => {
    expect(composeSudoStdin(Buffer.from('pw')).toString()).toBe('pw\n');
    expect(composeSudoStdin(Buffer.from('pw'), Buffer.alloc(0)).toString()).toBe('pw\n');
  });

  it('works with binary password and stdin buffers', () => {
    const password = Buffer.from([0x70, 0x77]);
    const stdin = Buffer.from([0x00, 0xff]);
    const composed = composeSudoStdin(password, stdin);
    expect(composed.subarray(0, 3)).toEqual(Buffer.from([0x70, 0x77, 0x0a]));
    expect(composed.subarray(3)).toEqual(stdin);
  });
});

describe('classifySudoRun', () => {
  it.each([
    'Sorry, try again.',
    'sudo: incorrect password attempt',
    'sudo: a password is required',
    'sudo: a terminal is required to read the password',
    'sudo: no tty present and no askpass program specified',
    'sudo: no password was provided',
  ])('recognizes sudo prompt output %j', (stderr) => {
    const err = classifySudoRun({ stderr });
    expect(err?.kind).toBe('SudoPrompt');
    expect(err?.code).toBe('sudo_prompt');
  });

  it('returns undefined for unrelated stderr', () => {
    expect(classifySudoRun({ stderr: 'bash: command not found' })).toBeUndefined();
    expect(classifySudoRun({ stderr: '' })).toBeUndefined();
  });
});

describe('isSudoCommand', () => {
  it.each([
    'sudo ls',
    'su -',
    'doas ls',
    'pkexec ls',
    'command sudo ls',
    'FOO=1 sudo ls',
    '/usr/bin/sudo ls',
  ])('recognizes %j', (command) => {
    expect(isSudoCommand(command)).toBe(true);
  });

  it.each(['ls', 'echo sudo', 'sudoedit file', 'ls && sudo reboot'])(
    'does not recognize %j as a leading sudo command',
    (command) => {
      expect(isSudoCommand(command)).toBe(false);
    },
  );
});

describe('stripLeadingSudoCommand', () => {
  it.each([
    ['sudo systemctl restart nginx', 'systemctl restart nginx'],
    ['sudo -n id', 'id'],
    ['sudo -S -k -- id', 'id'],
    ['sudo -u root systemctl status', 'systemctl status'],
    ['sudo --user=root systemctl status', 'systemctl status'],
    ['doas -u root id', 'id'],
    ['pkexec --user root id', 'id'],
    ['/usr/bin/sudo -n id', 'id'],
    ['su -c "systemctl status"', 'systemctl status'],
    ['su -c id', 'id'],
    ['FOO=1 sudo id', 'FOO=1 id'],
    ['command sudo id', 'command id'],
    ['sudo id; ls', 'id; ls'],
  ])('strips %j -> %j', (command, expected) => {
    expect(stripLeadingSudoCommand(command)).toBe(expected);
  });

  it('leaves non-sudo commands untouched', () => {
    expect(stripLeadingSudoCommand('systemctl status')).toBe('systemctl status');
    expect(stripLeadingSudoCommand('ls && sudo reboot')).toBe('ls && sudo reboot');
  });

  it('refuses unsafe/ambiguous prefixes instead of changing semantics', () => {
    // sudo 没有内部命令。
    expect(stripLeadingSudoCommand('sudo -n')).toBe('sudo -n');
    expect(stripLeadingSudoCommand('sudo')).toBe('sudo');
    // 选项缺少参数。
    expect(stripLeadingSudoCommand('sudo -u')).toBe('sudo -u');
    // su 依赖登录 shell / 用户语义，只有 -c 形式可安全剥离。
    expect(stripLeadingSudoCommand('su -')).toBe('su -');
    expect(stripLeadingSudoCommand('su root')).toBe('su root');
    expect(stripLeadingSudoCommand('su - root -c id')).toBe('su - root -c id');
  });
});
