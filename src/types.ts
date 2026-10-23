export type Alias = string & { readonly __brand: 'Alias' };

export type ErrorKind =
  | 'Policy'
  | 'Internal'
  | 'Timeout'
  | 'HostKey'
  | 'SudoPrompt'
  | 'Auth'
  | 'DNS'
  | 'TCP'
  | 'RemoteExit'
  | 'Unknown';

export interface ToolError {
  kind: ErrorKind;
  code: string;
  message: string;
  hint?: string;
  retryable: boolean;
  details?: Record<string, unknown>;
}

export interface SshSignatures {
  dns: boolean;
  tcp: boolean;
  auth: boolean;
  hostKeyUnknown: boolean;
  hostKeyChanged: boolean;
  sudoPrompt: boolean;
  connectionTimeout: boolean;
  other: string[];
}

export interface ErrorFacts {
  phase: 'trust' | 'preflight' | 'jump' | 'probe' | 'verify' | 'config';
  exitCode?: number | null;
  timedOut?: boolean;
  signal?: string | null;
  stderr?: string;
  spawnError?: { code: string; message: string };
  signatures?: SshSignatures;
  reason?: string;
}

export interface RunResult {
  argv: readonly string[];
  displayCommand: string;
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  timedOut: boolean;
  durationMs: number;
  spawnError?: { code: string; message: string };
}

export interface MCPPaths {
  configFile: string;
  configDir: string;
  knownHostsFile: string;
  trustRegistryFile: string;
  trustLockFile: string;
  source: 'flag' | 'env' | 'default';
}

export interface Defaults {
  port: number;
  defaultCwd: string;
  timeouts: { connectMs: number; commandMs: number; checkMs: number };
  maxOutputBytes: number;
  sudo: {
    mode: 'off' | 'passwordless' | 'password';
    credential?: string;
    allow: string[];
    deny: string[];
  };
}

export interface Security {
  hostKeyPolicy: 'pinned';
  knownHostsFile?: string;
}

export interface HostConfig {
  host: string;
  user: string;
  port?: number;
  identityFile?: string;
  proxyJump?: string;
  defaultCwd?: string;
  description?: string;
}

export interface RemoteConfig {
  version: 1;
  sourcePath: string;
  baseDir: string;
  defaults: Defaults;
  security: Security;
  hosts: Record<string, HostConfig>;
}

export interface EffectiveHost {
  alias: Alias;
  host: string;
  user: string;
  port: number;
  identityFile?: string;
  proxyJump?: string;
  cwd: string;
  timeouts: Defaults['timeouts'];
  maxOutputBytes: number;
  sudo: Defaults['sudo'];
}

export interface JumpSpec {
  user?: string;
  host: string;
  port?: number;
}

export interface Target {
  destination: string;
  jumps: JumpSpec[];
}

export interface KnownHostEntry {
  marker: '@cert-authority' | '@revoked' | null;
  hosts: string[];
  algorithm: string;
  keyBlob: string;
  raw: string;
  line: number;
}

export interface PinnedHostKey {
  algorithm: string;
  keyBlob: string;
  fingerprint: string;
  firstSeenAt: string;
  lastVerifiedAt: string;
}

export interface TrustRegistry {
  version: 1;
  hosts: Record<string, PinnedHostKey>;
}

export interface TrustDecision {
  action: 'initial' | 'unchanged' | 'rotate' | 'reject';
  observed: PinnedHostKey;
  pinned?: PinnedHostKey;
  reason?: string;
}

export interface CheckFacts {
  uname?: string;
  sshdVersion?: string;
  remoteExitCode?: number;
}

export interface HostView {
  alias: string;
  host: string;
  user: string;
  port: number;
  trusted: boolean;
  pinnedFingerprint?: string;
  knownHostsPresent: boolean;
  source: 'config';
  description?: string;
}

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export type LogMethod = (bindings: Record<string, unknown> | string, msg?: string) => void;

export interface Logger {
  debug: LogMethod;
  info: LogMethod;
  warn: LogMethod;
  error: LogMethod;
  child(bindings: Record<string, unknown>): Logger;
}
