import readline from 'node:readline';
import { TrustError, ConfigError } from '../errors/classes.js';
import { formatToolError, toUserError } from '../errors/classify.js';
import { makeToolError } from '../errors/taxonomy.js';
import { selectJumpSpec } from '../policy/target.js';
import { preflightAuth, preflightJump } from '../ssh/preflight.js';
import { probeHostKey, verifyTrustedConnection } from '../ssh/probe.js';
import type {
  Alias,
  EffectiveHost,
  ErrorFacts,
  Logger,
  MCPPaths,
  PinnedHostKey,
  ToolError,
  TrustDecision,
  TrustRegistry,
} from '../types.js';
import { decideTrust } from './decision.js';
import { fingerprintKey } from './fingerprint.js';
import { writeKnownHostsEntry } from './known-hosts.js';
import { acquireTrustLock, loadTrustRegistry, saveTrustRegistry } from './registry.js';

const CONFIRM_TIMEOUT_MS = 60_000;
const SERVER_KEY_CHECK_CMD = 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub';

export type ConfirmResult = { ok: true } | { ok: false; reason: 'declined' | 'fingerprint_mismatch' };

export interface ConfirmInput {
  preview: string;
  interactive: boolean;
  assumedFingerprint?: string;
  observed: PinnedHostKey;
  stdin?: NodeJS.ReadableStream;
  stdout?: NodeJS.WritableStream;
  timeoutMs?: number;
}

export interface TrustFlowDeps {
  preflightAuth: typeof preflightAuth;
  preflightJump: typeof preflightJump;
  probeHostKey: typeof probeHostKey;
  verifyTrustedConnection: typeof verifyTrustedConnection;
  loadRegistry: (file: string) => Promise<TrustRegistry>;
  saveRegistry: (file: string, reg: TrustRegistry) => Promise<void>;
  acquireLock: (file: string) => Promise<() => Promise<void>>;
  writeKnownHosts: typeof writeKnownHostsEntry;
  confirm: (input: ConfirmInput) => Promise<ConfirmResult>;
  render: (input: { alias: Alias; host: EffectiveHost; decision: TrustDecision }) => string;
}

export interface TrustFlowOptions {
  host: EffectiveHost;
  paths: MCPPaths;
  rotate: boolean;
  interactive: boolean;
  assumedFingerprint?: string;
  log: Logger;
  now?: () => Date;
  stdin?: NodeJS.ReadableStream;
  stdout?: NodeJS.WritableStream;
  sshPath?: string;
  deps?: Partial<TrustFlowDeps>;
}

export interface TrustFlowOutcome {
  ok: boolean;
  action: 'initial' | 'rotate' | 'unchanged' | 'rejected' | 'declined' | 'failed';
  alias: Alias;
  message: string;
  observed?: PinnedHostKey;
  pinned?: PinnedHostKey;
  error?: ToolError;
}

// ---------- 确认 ----------

/**
 * 交互：写 preview 与提示，逐行读 stdin，仅 trim 后严格等于 'yes' 才通过；EOF/超时/其他 -> declined。
 * 非交互：assumedFingerprint 必须与 observed.fingerprint 完全相等（大小写敏感，不允许省略前缀）。
 * 不抛。
 */
export async function confirmTrust(input: ConfirmInput): Promise<ConfirmResult> {
  try {
    if (!input.interactive) {
      const expected = input.assumedFingerprint;
      if (expected === undefined || expected !== input.observed.fingerprint) {
        return { ok: false, reason: 'fingerprint_mismatch' };
      }
      return { ok: true };
    }
    const stdin = input.stdin ?? process.stdin;
    const stdout = input.stdout ?? process.stdout;
    const timeoutMs = input.timeoutMs ?? CONFIRM_TIMEOUT_MS;
    stdout.write(`${input.preview}\nType "yes" to trust this host: `);

    return await new Promise<ConfirmResult>((resolve) => {
      let settled = false;
      let timer: NodeJS.Timeout | undefined;
      const rl = readline.createInterface({ input: stdin, terminal: false });
      const finish = (result: ConfirmResult): void => {
        if (settled) return;
        settled = true;
        if (timer !== undefined) clearTimeout(timer);
        rl.close();
        resolve(result);
      };
      timer = setTimeout(() => finish({ ok: false, reason: 'declined' }), timeoutMs);
      rl.on('line', (line) => {
        finish(line.trim() === 'yes' ? { ok: true } : { ok: false, reason: 'declined' });
      });
      rl.on('close', () => finish({ ok: false, reason: 'declined' }));
    });
  } catch {
    return { ok: false, reason: 'declined' };
  }
}

// ---------- 预览 ----------

/** 多行预览：别名、目标、算法、观察到的指纹；rotate 时附旧指纹；提示服务器端比对命令。 */
export function renderTrustPreview(input: { alias: Alias; host: EffectiveHost; decision: TrustDecision }): string {
  const { alias, host, decision } = input;
  const lines = [
    `主机别名: ${alias}`,
    `连接目标: ${host.user}@${host.host}:${host.port}`,
    `密钥算法: ${decision.observed.algorithm}`,
    `观察到的指纹: ${decision.observed.fingerprint}`,
  ];
  if (decision.action === 'rotate' && decision.pinned !== undefined) {
    lines.push(`已固定的旧指纹: ${decision.pinned.fingerprint}`);
    lines.push('警告：该主机指纹已变化。仅当你确认服务器密钥已合法更换（如重装系统）时才继续。');
  } else {
    lines.push('状态: 首次信任（尚未登记该主机的指纹）');
  }
  lines.push('请在服务器上执行以下命令，并与上方指纹比对：');
  lines.push(`  ${SERVER_KEY_CHECK_CMD}`);
  return lines.join('\n');
}

// ---------- 主流程 ----------

const DEFAULT_DEPS: TrustFlowDeps = {
  preflightAuth,
  preflightJump,
  probeHostKey,
  verifyTrustedConnection,
  loadRegistry: loadTrustRegistry,
  saveRegistry: saveTrustRegistry,
  acquireLock: acquireTrustLock,
  writeKnownHosts: writeKnownHostsEntry,
  confirm: confirmTrust,
  render: renderTrustPreview,
};

function own<T>(map: Record<string, T>, key: string): T | undefined {
  return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : undefined;
}

/** 由事实生成失败结果：message 为自定义摘要 + formatToolError。 */
function failWithFact(
  alias: Alias,
  fact: ErrorFacts,
  summary: string,
  extra?: { observed?: PinnedHostKey; pinned?: PinnedHostKey },
): TrustFlowOutcome {
  const error = toUserError(fact);
  return {
    ok: false,
    action: 'failed',
    alias,
    message: `${summary}\n${formatToolError(error, alias)}`,
    error,
    ...extra,
  };
}

function failureFromException(e: unknown, alias: Alias): TrustFlowOutcome {
  const trustCode = e instanceof TrustError ? e.code : undefined;
  const isConfig = e instanceof ConfigError;
  const text = e instanceof Error ? e.message : String(e);
  const error = toUserError({ phase: 'trust', reason: trustCode ?? (isConfig ? 'config_io' : 'internal'), stderr: text });
  error.message = e instanceof TrustError || isConfig ? text : '信任流程内部错误';
  if (trustCode === 'lock_busy') error.hint = '另一个信任操作正在进行，稍后重试。';
  if (isConfig) error.hint = '信任注册表或 known_hosts 文件损坏或不可读，请检查后重试。';
  return { ok: false, action: 'failed', alias, message: formatToolError(error, alias), error };
}

/**
 * 信任流程：预检 -> 探测主机密钥 -> 与注册表决策 -> 确认 -> 加锁二次决策并写入 -> 严格验证。
 * 不抛：所有异常转为 ok:false。
 */
export async function runTrustFlow(o: TrustFlowOptions): Promise<TrustFlowOutcome> {
  const d: TrustFlowDeps = { ...DEFAULT_DEPS, ...stripUndefined(o.deps) };
  const alias = o.host.alias;
  try {
    return await runSteps(o, d);
  } catch (e) {
    return failureFromException(e, alias);
  }
}

function stripUndefined(deps: Partial<TrustFlowDeps> | undefined): Partial<TrustFlowDeps> {
  const out: Partial<TrustFlowDeps> = {};
  if (deps === undefined) return out;
  for (const key of Object.keys(deps) as (keyof TrustFlowDeps)[]) {
    if (deps[key] !== undefined) (out as Record<string, unknown>)[key] = deps[key];
  }
  return out;
}

async function runSteps(o: TrustFlowOptions, d: TrustFlowDeps): Promise<TrustFlowOutcome> {
  const { host, paths, log, sshPath } = o;
  const alias = host.alias;
  const now = (o.now ?? (() => new Date()))().toISOString();

  // 1. 跳板预检
  const jumps = selectJumpSpec(host.proxyJump);
  if (jumps.length > 0) {
    const jr = await d.preflightJump({ host, jumps, log });
    if (!jr.ok) return failWithFact(alias, jr.fact, '跳板机前置检查失败：请先确保各跳主机已在 known_hosts 中。');
  }

  // 2. 认证预检（P1：认证不可用即拒绝，即便认证失败本身不影响主机指纹信任）
  const ar = await d.preflightAuth({ host, paths, log });
  if (!ar.ok) {
    return failWithFact(
      alias,
      ar.fact,
      '认证前置检查失败：P1 要求认证可用（identity_file 可读或 ssh-agent 中有可用密钥）后才能建立信任。',
    );
  }

  // 3. 探测主机密钥（临时 known_hosts，accept-new）
  const probe = await d.probeHostKey({ host, paths, timeoutMs: host.timeouts.connectMs, log, sshPath });
  if (!probe.ok) return failWithFact(alias, probe.fact, '无法探测远端主机密钥。');
  if (probe.entries.length !== 1) {
    return failWithFact(
      alias,
      { phase: 'probe', reason: 'probe_ambiguous' },
      `探测到 ${probe.entries.length} 条主机密钥（应恰好 1 条），拒绝继续。`,
    );
  }
  const entry = probe.entries[0];
  if (entry === undefined) throw new TrustError('probe_ambiguous', 'probe returned no entry');
  const observed: PinnedHostKey = {
    algorithm: entry.algorithm,
    keyBlob: entry.keyBlob,
    fingerprint: fingerprintKey(entry.algorithm, entry.keyBlob),
    firstSeenAt: now,
    lastVerifiedAt: now,
  };

  // 4. 读注册表并决策
  const reg = await d.loadRegistry(paths.trustRegistryFile);
  const pinned = own(reg.hosts, alias);
  const decision = decideTrust({ alias, observed, pinned, rotate: o.rotate });
  log.debug({ alias, action: decision.action }, 'trust decision');

  if (decision.action === 'reject') {
    const error = toUserError({ phase: 'trust', reason: 'fingerprint_mismatch' });
    const summary = [
      `主机 ${alias} 的指纹与已固定的不一致，已拒绝（未写入任何内容）。`,
      `已固定指纹: ${decision.pinned?.fingerprint ?? '(无)'}`,
      `观察到的指纹: ${observed.fingerprint}`,
      `若确认服务器密钥合法变更（例如重装），运行 \`remote-mcp trust ${alias} --rotate\`。`,
    ].join('\n');
    return {
      ok: false,
      action: 'rejected',
      alias,
      observed,
      pinned: decision.pinned,
      message: `${summary}\n${formatToolError(error, alias)}`,
      error,
    };
  }

  if (decision.action === 'unchanged') {
    const v = await d.verifyTrustedConnection({ host, paths, log, sshPath });
    if (!v.ok) {
      return failWithFact(alias, v.fact, '指纹未变化（已信任），但认证验证失败。', { observed, pinned: decision.pinned });
    }
    return {
      ok: true,
      action: 'unchanged',
      alias,
      observed,
      pinned: decision.pinned,
      message: `主机 ${alias} 的指纹已信任且未变化，连接验证通过。`,
    };
  }

  // 5. initial / rotate：预览并确认
  const preview = d.render({ alias, host, decision });
  const confirmed = await d.confirm({
    preview,
    interactive: o.interactive,
    assumedFingerprint: o.assumedFingerprint,
    observed,
    stdin: o.stdin,
    stdout: o.stdout,
  });
  if (!confirmed.ok) {
    const isMismatch = confirmed.reason === 'fingerprint_mismatch';
    const error = makeToolError('HostKey', {
      code: isMismatch ? 'fingerprint_mismatch' : 'declined',
      message: isMismatch ? '提供的指纹与观察到的指纹不一致' : '用户未确认信任',
    });
    const text = isMismatch
      ? '非交互模式下 --fingerprint 与观察到的指纹不一致，未写入任何内容。'
      : '用户未确认信任，未写入任何内容。';
    return {
      ok: false,
      action: 'declined',
      alias,
      observed,
      pinned: decision.pinned,
      message: `${text}\n${formatToolError(error, alias)}`,
      error,
    };
  }

  // 6. 加锁、二次决策（防并发改写）、写 known_hosts 与注册表
  const release = await d.acquireLock(paths.trustLockFile);
  let finalPinned: PinnedHostKey;
  try {
    const reg2 = await d.loadRegistry(paths.trustRegistryFile);
    const pinned2 = own(reg2.hosts, alias);
    const decision2 = decideTrust({ alias, observed, pinned: pinned2, rotate: o.rotate });
    if (decision2.action === 'reject') {
      const error = toUserError({ phase: 'trust', reason: 'fingerprint_mismatch' });
      return {
        ok: false,
        action: 'rejected',
        alias,
        observed,
        pinned: pinned2,
        message: `确认期间注册表被修改，指纹不再匹配，已拒绝。\n${formatToolError(error, alias)}`,
        error,
      };
    }
    if (pinned2?.fingerprint !== decision.pinned?.fingerprint) {
      const error = makeToolError('HostKey', {
        code: 'lock_busy',
        message: '确认期间注册表已被修改',
      });
      return {
        ok: false,
        action: 'failed',
        alias,
        observed,
        message: `确认期间注册表已被其他操作修改，未写入。请重新运行 trust。\n${formatToolError(error, alias)}`,
        error,
      };
    }

    const firstSeenAt = decision2.pinned?.firstSeenAt ?? now;
    await d.writeKnownHosts({
      file: paths.knownHostsFile,
      host: host.host,
      port: host.port,
      algorithm: observed.algorithm,
      keyBlob: observed.keyBlob,
      mode: 'replace-host',
    });
    const next: TrustRegistry = {
      version: 1,
      hosts: {
        ...reg2.hosts,
        [alias]: {
          algorithm: observed.algorithm,
          keyBlob: observed.keyBlob,
          fingerprint: observed.fingerprint,
          firstSeenAt,
          lastVerifiedAt: now,
        },
      },
    };
    await d.saveRegistry(paths.trustRegistryFile, next);
    finalPinned = next.hosts[alias] as PinnedHostKey;
  } finally {
    await release();
  }

  // 7. 严格验证
  const action = decision.action === 'rotate' ? 'rotate' : 'initial';
  const v = await d.verifyTrustedConnection({ host, paths, log, sshPath });
  if (!v.ok) {
    const error = toUserError(v.fact, log);
    return {
      ok: false,
      action: 'failed',
      alias,
      observed,
      pinned: finalPinned,
      message: `指纹已写入，但认证验证失败（主机 ${alias}）。请检查认证配置后重试。\n${formatToolError(error, alias)}`,
      error,
    };
  }

  const verb = action === 'rotate' ? '已轮换' : '已首次信任';
  return {
    ok: true,
    action,
    alias,
    observed,
    pinned: finalPinned,
    message: `${verb}主机 ${alias}：指纹 ${observed.fingerprint} 已写入 known_hosts 与注册表，连接验证通过。`,
  };
}
