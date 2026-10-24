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
  phase: 'trust' | 'preflight' | 'jump' | 'probe' | 'verify' | 'config' | 'exec';
  exitCode?: number | null;
  timedOut?: boolean;
  signal?: string | null;
  stderr?: string;
  spawnError?: { code: string; message: string };
  signatures?: SshSignatures;
  reason?: string;
}

/** 文件模式下本地 I/O 失败（打开/读取/写入）；仅在 stdinFile/stdoutFile 出错时存在。 */
export interface RunIoError {
  stream: 'stdin' | 'stdout';
  code: string;
  message: string;
}

export interface RunResult {
  argv: readonly string[];
  displayCommand: string;
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  /** Total bytes actually received from the stream (including truncated bytes). */
  stdoutBytes: number;
  /** Total bytes actually received from the stream (including truncated bytes). */
  stderrBytes: number;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  timedOut: boolean;
  durationMs: number;
  spawnError?: { code: string; message: string };
  /** stdinFile/stdoutFile 模式下的本地文件错误；spawn 前打开失败或流式读写出错。 */
  ioError?: RunIoError;
}

export interface MCPPaths {
  configFile: string;
  configDir: string;
  knownHostsFile: string;
  trustRegistryFile: string;
  trustLockFile: string;
  source: 'flag' | 'env' | 'default';
}

/** P3 文件传输的全局策略（展开后的默认值）。 */
export interface FilesConfig {
  /** 本地可读/可写的根目录（绝对路径）；空数组表示不允许任何本地路径。 */
  localRoots: string[];
  /** 远端禁止访问的前缀（以 / 或 ~ 开头）。 */
  remoteDeny: string[];
  maxFileBytes: number;
  maxFiles: number;
  maxTotalBytes: number;
  maxDepth: number;
  transferTimeoutMs: number;
}

export interface Defaults {
  port: number;
  defaultCwd: string;
  defaultHost?: string;
  timeouts: { connectMs: number; commandMs: number; checkMs: number };
  maxOutputBytes: number;
  sudo: {
    mode: 'off' | 'passwordless' | 'password';
    credential?: string;
    /** 原始规则文本（保留用于展示/审计）。 */
    allow: string[];
    deny: string[];
    /** 加载期预编译的规则；手工构造 Defaults 时可省略，求值时再解析。 */
    allowRules?: CommandRule[];
    denyRules?: CommandRule[];
  };
  files: FilesConfig;
}

/** 命令策略中的一条规则（内置 / 配置 / sudo）。 */
export interface CommandRule {
  raw: string;
  kind: 'prefix' | 're';
  source: 'builtin' | 'config' | 'sudo';
  id: string;
  regex?: RegExp;
  prefix?: string;
  dangerous?: boolean;
  hard?: boolean;
}

/** P5 命令策略（展开后的默认值）。 */
export interface CommandPolicy {
  mode: 'off' | 'enforce' | 'read_only';
  useDefaultDeny: boolean;
  allow: CommandRule[];
  confirm: CommandRule[];
  deny: CommandRule[];
}

/** 一次策略求值的结论。surface 标明调用来自哪个工具入口。 */
export interface CommandDecision {
  action: 'allow' | 'deny' | 'confirm';
  code: string;
  ruleId?: string;
  reason: string;
  surface: 'ssh_exec' | 'session_send' | 'ssh_sudo';
}

/** security.audit 展开后的默认值。 */
export interface AuditConfig {
  maxBytes: number;
  retainDays: number;
  dateRotate: boolean;
}

export interface Security {
  hostKeyPolicy: 'pinned';
  knownHostsFile?: string;
  commandPolicy: CommandPolicy;
  audit: AuditConfig;
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
  /** 与 defaults.files 指向同一对象。 */
  files: FilesConfig;
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
