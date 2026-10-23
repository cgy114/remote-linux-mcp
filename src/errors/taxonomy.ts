import type { ErrorFacts, ErrorKind, ToolError } from '../types.js';

export interface ErrorTaxonomyEntry {
  code: string;
  retryable: boolean;
  hint: string;
  exitCode: number;
}

const TAXONOMY: Record<ErrorKind, ErrorTaxonomyEntry> = {
  Policy: {
    code: 'policy_denied',
    retryable: false,
    hint: '检查 remote-mcp 配置中该 host 的定义与策略（alias 是否存在、allow/deny 规则）。',
    exitCode: 2,
  },
  Internal: {
    code: 'internal_error',
    retryable: false,
    hint: '本地无法启动 ssh 进程。检查 ssh 是否已安装且在 PATH 中，并查看日志（REMOTE_MCP_LOG_LEVEL=debug）。',
    exitCode: 1,
  },
  Timeout: {
    code: 'timeout',
    retryable: true,
    hint: '连接或命令超时。检查网络与目标主机负载后重试；必要时调大 timeouts 配置。',
    exitCode: 1,
  },
  HostKey: {
    code: 'host_key',
    retryable: false,
    hint: '远端主机密钥未受信任或已变化。若确认密钥合法，运行 `remote-mcp trust <alias>`；否则不要继续，排查中间人风险。',
    exitCode: 4,
  },
  SudoPrompt: {
    code: 'sudo_prompt',
    retryable: false,
    hint: '远端 sudo 需要密码但无法交互输入。为该用户配置 NOPASSWD，或在 sudo.mode=password 下提供 credential。',
    exitCode: 4,
  },
  Auth: {
    code: 'auth_failed',
    retryable: false,
    hint: '认证失败。检查 identity_file 指向的私钥是否正确、权限是否为 600，并用 `ssh-add -l` 确认 agent 中已加载对应密钥。',
    exitCode: 4,
  },
  DNS: {
    code: 'dns_failed',
    retryable: true,
    hint: '无法解析主机名。检查 host 拼写，以及 DNS、VPN 或代理设置。',
    exitCode: 4,
  },
  TCP: {
    code: 'tcp_failed',
    retryable: true,
    hint: '无法建立 TCP 连接。检查端口、防火墙、目标 sshd 是否在运行，以及网络路由。',
    exitCode: 4,
  },
  RemoteExit: {
    code: 'remote_exit',
    retryable: false,
    hint: '远端命令以非零退出码结束。查看 stdout/stderr 定位命令本身的错误。',
    exitCode: 1,
  },
  Unknown: {
    code: 'unknown',
    retryable: false,
    hint: '未识别的错误。以 REMOTE_MCP_LOG_LEVEL=debug 重试并查看日志获取详情。',
    exitCode: 1,
  },
};

const DEFAULT_MESSAGES: Record<ErrorKind, string> = {
  Policy: '策略或配置不允许该操作',
  Internal: '本地内部错误',
  Timeout: '操作超时',
  HostKey: '远端主机密钥未受信任',
  SudoPrompt: '远端 sudo 需要交互式密码',
  Auth: '认证失败',
  DNS: '主机名解析失败',
  TCP: 'TCP 连接失败',
  RemoteExit: '远端命令非零退出',
  Unknown: '未知错误',
};

/** 按类别返回稳定的 code / retryable / hint / exitCode。返回值为副本，调用方修改不影响全局表。 */
export function errorTaxonomy(kind: ErrorKind): ErrorTaxonomyEntry {
  const entry = TAXONOMY[kind];
  return { ...entry };
}

/** 构造 ToolError。code 可被 detail.code 覆盖；message 默认取类别的简短描述；details 原样合并。 */
export function makeToolError(
  kind: ErrorKind,
  detail?: { code?: string; message?: string; details?: Record<string, unknown> },
): ToolError {
  const tax = errorTaxonomy(kind);
  const err: ToolError = {
    kind,
    code: detail?.code ?? tax.code,
    message: detail?.message ?? DEFAULT_MESSAGES[kind],
    hint: tax.hint,
    retryable: tax.retryable,
  };
  if (detail?.details !== undefined) {
    err.details = { ...detail.details };
  }
  return err;
}

/**
 * 可重试性。DNS/TCP 在本地阶段（trust/preflight）没有网络语义，视为不可重试；
 * 其余直接取 taxonomy 的基础值。
 */
export function isRetryable(kind: ErrorKind, phase: ErrorFacts['phase']): boolean {
  const base = errorTaxonomy(kind).retryable;
  if ((kind === 'DNS' || kind === 'TCP') && (phase === 'trust' || phase === 'preflight')) {
    return false;
  }
  return base;
}
