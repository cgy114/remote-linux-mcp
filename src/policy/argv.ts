import path from 'node:path';
import type { EffectiveHost } from '../types.js';

export type SshMode = 'strict' | 'accept-new';

// Only these characters are emitted unquoted in the display string.
const DISPLAY_SAFE_RE = /^[A-Za-z0-9_\-.,:/=@%+]+$/;

/**
 * Hardening options shared by every ssh invocation. Each option is emitted as
 * its own argv pair ("-o", "Key=value") so no shell or option-splitting is involved.
 */
export function baseSshOptions(input: {
  knownHostsFile: string;
  connectMs: number;
  mode: SshMode;
}): readonly string[] {
  if (!path.isAbsolute(input.knownHostsFile)) {
    throw new Error('knownHostsFile must be an absolute path');
  }
  return [
    '-o', 'BatchMode=yes',
    '-o', `ConnectTimeout=${Math.ceil(input.connectMs / 1000)}`,
    '-o', 'ServerAliveInterval=15',
    '-o', 'ServerAliveCountMax=3',
    '-o', `StrictHostKeyChecking=${input.mode === 'strict' ? 'yes' : 'accept-new'}`,
    '-o', `UserKnownHostsFile=${input.knownHostsFile}`,
    '-o', 'GlobalKnownHostsFile=none',
    '-o', 'CheckHostIP=no',
    '-o', 'UpdateHostKeys=no',
    '-o', 'HashKnownHosts=no',
    '-o', 'ControlMaster=no',
    '-o', 'ControlPath=none',
    '-T',
  ];
}

/**
 * Builds ssh arguments (without the executable path, which runSsh prepends).
 * Order: hardening options, optional -p, caller extras, "--", destination, remoteCommand.
 */
export function buildSshArgv(input: {
  host: EffectiveHost;
  knownHostsFile: string;
  remoteCommand?: string;
  extra?: readonly string[];
  mode: SshMode;
}): { argv: string[]; display: string } {
  const { host } = input;
  const argv: string[] = [
    ...baseSshOptions({
      knownHostsFile: input.knownHostsFile,
      connectMs: host.timeouts.connectMs,
      mode: input.mode,
    }),
  ];
  if (host.port !== 22) {
    argv.push('-p', String(host.port));
  }
  if (input.extra !== undefined) {
    argv.push(...input.extra);
  }
  argv.push('--', `${host.user}@${host.host}`);
  if (input.remoteCommand !== undefined) {
    argv.push(input.remoteCommand);
  }
  assertArgvSafe(argv);
  const display = ['ssh', ...argv].map(quoteForDisplay).join(' ');
  return { argv, display };
}

/** `ssh -G <destination>` argv for resolving effective client config. */
export function buildSshGArgv(host: EffectiveHost): string[] {
  return ['-G', `${host.user}@${host.host}`];
}

/**
 * Rejects argv that would be unsafe to spawn: empty, containing NUL, or where the
 * first item after "--" looks like an option.
 */
export function assertArgvSafe(argv: readonly string[]): void {
  if (argv.length === 0) {
    throw new Error('argv must not be empty');
  }
  for (const item of argv) {
    if (item.includes('\u0000')) {
      throw new Error('argv contains a NUL byte');
    }
  }
  const sep = argv.indexOf('--');
  if (sep !== -1) {
    const next = argv[sep + 1];
    if (next !== undefined && next.startsWith('-')) {
      throw new Error('the item after "--" must not start with "-"');
    }
  }
}

function quoteForDisplay(arg: string): string {
  if (arg.length > 0 && DISPLAY_SAFE_RE.test(arg)) return arg;
  return `'${arg.split("'").join(`'\\''`)}'`;
}
