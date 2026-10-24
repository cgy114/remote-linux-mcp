import { ConfigError } from '../errors/classes.js';
import type { CommandPolicy, CommandRule } from '../types.js';
import { BUILTIN_RULE_DEFS, builtinReason } from './command-defaults.js';
import { tokenize } from './command-scan.js';

export interface RawCommandPolicy {
  mode?: 'off' | 'enforce' | 'read_only';
  use_default_deny?: boolean;
  allow?: readonly string[];
  confirm?: readonly string[];
  deny?: readonly string[];
}

const RE_MARKER = 're:';
const PREFIX_MARKER = 'prefix:';

/**
 * 解析单条规则。
 * - `re:<pattern>`：编译为非锚定正则；非法正则抛 ConfigError('schema')。
 * - `prefix:<text>` / 裸 `<text>`：按 token 前缀匹配。
 * 空规则一律拒绝。
 */
export function parseRule(spec: unknown, source: CommandRule['source'], id: string): CommandRule {
  if (typeof spec !== 'string') {
    throw new ConfigError('schema', `command rule ${id} must be a string`);
  }
  const raw = spec.trim();
  if (raw.length === 0) {
    throw new ConfigError('schema', `command rule ${id} is empty`);
  }

  if (raw.startsWith(RE_MARKER)) {
    const pattern = raw.slice(RE_MARKER.length).trim();
    if (pattern.length === 0) {
      throw new ConfigError('schema', `command rule ${id} has an empty regex`);
    }
    let regex: RegExp;
    try {
      regex = new RegExp(pattern);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new ConfigError('schema', `command rule ${id} has an invalid regex: ${message}`, {
        cause: err,
      });
    }
    return { raw, kind: 're', source, id, regex };
  }

  const body = raw.startsWith(PREFIX_MARKER) ? raw.slice(PREFIX_MARKER.length).trim() : raw;
  const tokens = tokenize(body).filter((token) => token.length > 0);
  if (tokens.length === 0) {
    throw new ConfigError('schema', `command rule ${id} has an empty prefix`);
  }
  return { raw, kind: 'prefix', source, id, prefix: tokens.join(' ') };
}

/** 规则前缀的 token 数组；非 prefix 规则返回空数组。 */
export function rulePrefixTokens(rule: CommandRule): string[] {
  if (rule.kind !== 'prefix' || rule.prefix === undefined) return [];
  return tokenize(rule.prefix).filter((token) => token.length > 0);
}

function parseRules(specs: readonly string[] | undefined, tier: string): CommandRule[] {
  if (specs === undefined) return [];
  return specs.map((spec, index) => parseRule(spec, 'config', `${tier}[${index}]`));
}

/** 内置危险规则（带 hard / dangerous 元数据）。 */
export function builtinCommandRules(): CommandRule[] {
  return BUILTIN_RULE_DEFS.map((def) => {
    const rule = parseRule(def.spec, 'builtin', def.id);
    if (def.hard === true) rule.hard = true;
    if (def.dangerous === true) rule.dangerous = true;
    return rule;
  });
}

/**
 * 合并内置危险表与配置规则，产出展开后的 CommandPolicy。
 * useDefaultDeny=false 时完全移除内置 deny 规则。
 */
export function compileCommandPolicy(raw: RawCommandPolicy): CommandPolicy {
  const mode = raw.mode ?? 'enforce';
  const useDefaultDeny = raw.use_default_deny ?? true;
  const deny: CommandRule[] = [];
  if (useDefaultDeny) deny.push(...builtinCommandRules());
  deny.push(...parseRules(raw.deny, 'deny'));
  return {
    mode,
    useDefaultDeny,
    allow: parseRules(raw.allow, 'allow'),
    confirm: parseRules(raw.confirm, 'confirm'),
    deny,
  };
}

/** 规则命中时使用的中文 reason。 */
export function commandRuleReason(rule: CommandRule): string {
  if (rule.source === 'builtin') {
    return builtinReason(rule.id) ?? `命中内置规则 ${rule.id}`;
  }
  return `命中规则 ${rule.id}：${rule.raw}`;
}

const SENSITIVE_ENV_KEYS: ReadonlySet<string> = new Set([
  'PATH',
  'BASH_ENV',
  'ENV',
  'LD_PRELOAD',
  'LD_LIBRARY_PATH',
  'LD_AUDIT',
  'SHELLOPTS',
  'BASHOPTS',
  'IFS',
  'CDPATH',
  'GLOBIGNORE',
  'PROMPT_COMMAND',
  'PS4',
  'GIT_SSH_COMMAND',
  'GIT_PAGER',
  'PAGER',
  'SSH_ASKPASS',
  'DISPLAY',
]);

/** 该环境变量会改变 shell / 程序的执行语义，read_only 下禁止。 */
export function isSensitiveEnvKey(key: string): boolean {
  return SENSITIVE_ENV_KEYS.has(key);
}

const FORBIDDEN_PROGRAMS: ReadonlySet<string> = new Set([
  // 提权
  'sudo',
  'su',
  'doas',
  'pkexec',
  // shell / 通用解释器
  'bash',
  'sh',
  'dash',
  'zsh',
  'ksh',
  'fish',
  'csh',
  'tcsh',
  'python',
  'python2',
  'python3',
  'pypy',
  'pypy3',
  'perl',
  'ruby',
  'node',
  'nodejs',
  'deno',
  'bun',
  'awk',
  'gawk',
  'mawk',
  'nawk',
  // 包装器 / 命令通道
  'env',
  'xargs',
  'find',
  'sed',
  'tar',
  'rsync',
  'scp',
  'ssh',
  'nc',
  'netcat',
  'ncat',
  'socat',
  'curl',
  'wget',
  'docker',
  'busybox',
  // shell 内建 / 控制结构
  'eval',
  'exec',
  'source',
  '.',
  'command',
  'builtin',
  'export',
  'set',
  'unset',
  'alias',
  'trap',
]);

/** 首 token 是否属于硬拒绝的解释器 / 包装器 / 提权程序（按 basename 比较）。 */
export function isForbiddenProgram(token: string): boolean {
  if (token.length === 0) return false;
  const normalized = token.toLowerCase();
  const base = normalized.includes('/') ? (normalized.split('/').pop() ?? normalized) : normalized;
  return FORBIDDEN_PROGRAMS.has(base);
}
