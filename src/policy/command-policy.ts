import { UsageError } from '../errors/classes.js';
import type { CommandDecision, CommandPolicy, CommandRule, Defaults } from '../types.js';
import {
  commandRuleReason,
  isForbiddenProgram,
  isSensitiveEnvKey,
  parseRule,
  rulePrefixTokens,
} from './command-rules.js';
import {
  hasRedirection,
  hasUnsafeConstruct,
  leadingWords,
  normalizeSkeleton,
  splitSegments,
  stripLeadingNoise,
  tokenize,
  type CommandSegment,
} from './command-scan.js';

export type CommandSurface = CommandDecision['surface'];

export interface EvaluateCommandPolicyInput {
  command: string;
  policy: CommandPolicy;
  surface: CommandSurface;
  /** 由工具传入的环境变量名（键）。 */
  envKeys?: readonly string[];
}

export interface EvaluateSudoPolicyInput {
  command: string;
  sudo: Defaults['sudo'];
  surface: CommandSurface;
  /** 调用方当前的命令策略模式；read_only 时 sudo 一律拒绝。 */
  policyMode?: CommandPolicy['mode'];
}

interface ScanContext {
  rawSegments: CommandSegment[];
  /** deny 扫描的候选文本与片段：原始、骨架、去引号、剥离开头包装后的变体。 */
  denyTexts: string[];
  denySegments: CommandSegment[];
}

function makeDecision(
  action: CommandDecision['action'],
  code: string,
  reason: string,
  surface: CommandSurface,
  ruleId?: string,
): CommandDecision {
  const decision: CommandDecision = { action, code, reason, surface };
  if (ruleId !== undefined) decision.ruleId = ruleId;
  return decision;
}

function scanContext(command: string): ScanContext {
  const skeleton = normalizeSkeleton(command);
  // 去引号变体只用于 deny 扫描：`rm -rf "/"`、`rm '-rf' /` 也应按危险命令处理。
  const dequoted = skeleton.replace(/['"]/g, '');
  const rawSegments = splitSegments(command);
  const skelSegments = splitSegments(skeleton);
  const dequotedSegments = splitSegments(dequoted);
  const allSegments = [...rawSegments, ...skelSegments, ...dequotedSegments];
  const strippedSegments = allSegments
    .map((segment) => ({ ...segment, text: stripLeadingNoise(segment.text) }))
    .filter((segment) => segment.text.length > 0);

  const textSet = new Set<string>([
    command,
    skeleton,
    dequoted,
    stripLeadingNoise(command),
    stripLeadingNoise(skeleton),
    stripLeadingNoise(dequoted),
  ]);
  for (const segment of [...allSegments, ...strippedSegments]) {
    if (segment.text.length > 0) textSet.add(segment.text);
  }

  return {
    rawSegments,
    denyTexts: [...textSet],
    denySegments: [...allSegments, ...strippedSegments],
  };
}

function programBase(token: string): string {
  const lower = token.toLowerCase();
  return lower.includes('/') ? (lower.split('/').pop() ?? lower) : lower;
}

function prefixMatches(rule: CommandRule, text: string): boolean {
  const needed = rulePrefixTokens(rule);
  if (needed.length === 0) return false;
  const got = leadingWords(text, needed.length);
  if (got.length !== needed.length) return false;
  // 首词允许用 basename 比较：`/bin/sh` 应命中 `sh`，且不依赖远端安装路径。
  return needed.every((token, index) => {
    const actual = got[index] ?? '';
    return actual === token || (index === 0 && programBase(actual) === programBase(token));
  });
}

function ruleMatchesText(rule: CommandRule, text: string): boolean {
  if (rule.kind === 're') {
    return rule.regex !== undefined && rule.regex.test(text);
  }
  return prefixMatches(rule, text);
}

/** 命中任意一条规则（prefix 看片段首词；re 看整条命令与所有扫描变体）。 */
function findRule(rules: readonly CommandRule[], context: ScanContext): CommandRule | undefined {
  for (const rule of rules) {
    if (rule.kind === 're') {
      if (rule.regex === undefined) continue;
      if (context.denyTexts.some((text) => rule.regex!.test(text))) return rule;
      continue;
    }
    if (context.denySegments.some((segment) => prefixMatches(rule, segment.text))) return rule;
  }
  return undefined;
}

function segmentMatchesAny(rules: readonly CommandRule[], segment: CommandSegment): boolean {
  return rules.some((rule) => ruleMatchesText(rule, segment.text));
}

function leadingAssignmentKeys(segment: string): string[] {
  const tokens = tokenize(segment);
  const keys: string[] = [];
  for (const token of tokens) {
    const match = /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(token);
    if (match === null) break;
    keys.push(match[1] ?? '');
  }
  return keys;
}

/** read_only 的结构性拒绝：后台、重定向、unsafe construct、敏感 env、禁用程序。 */
function readOnlyStructuralDeny(
  input: EvaluateCommandPolicyInput,
  context: ScanContext,
): CommandDecision | undefined {
  const surface = input.surface;
  if (input.policy.allow.length === 0) {
    return makeDecision(
      'deny',
      'policy_read_only_allowlist_empty',
      'read_only 模式未配置 allow 规则，拒绝所有命令',
      surface,
    );
  }
  const envKeys = input.envKeys ?? [];
  for (const key of envKeys) {
    if (isSensitiveEnvKey(key)) {
      return makeDecision(
        'deny',
        'policy_read_only_env',
        `read_only 模式禁止设置敏感环境变量 ${key}`,
        surface,
      );
    }
  }

  if (context.rawSegments.length === 0) {
    return makeDecision('deny', 'policy_not_allowed', 'read_only 模式不允许空命令', surface);
  }

  for (const segment of context.rawSegments) {
    if (segment.separator === '&') {
      return makeDecision('deny', 'policy_read_only_unsafe', 'read_only 模式禁止后台执行', surface);
    }
    if (segment.unsafe || hasUnsafeConstruct(segment.text)) {
      return makeDecision(
        'deny',
        'policy_read_only_unsafe',
        'read_only 模式禁止命令替换、反引号、进程替换、函数定义或 shell 控制内建',
        surface,
      );
    }
    if (hasRedirection(segment.text)) {
      return makeDecision('deny', 'policy_read_only_unsafe', 'read_only 模式禁止重定向', surface);
    }
    for (const key of leadingAssignmentKeys(segment.text)) {
      if (isSensitiveEnvKey(key)) {
        return makeDecision(
          'deny',
          'policy_read_only_env',
          `read_only 模式禁止设置敏感环境变量 ${key}`,
          surface,
        );
      }
    }
    const first = leadingWords(segment.text, 1)[0];
    if (first !== undefined && isForbiddenProgram(first)) {
      return makeDecision(
        'deny',
        'policy_read_only_unsafe',
        `read_only 模式禁止调用解释器/包装器/提权程序 ${first}`,
        surface,
      );
    }
  }
  return undefined;
}

/**
 * 求值命令策略。绝不抛异常；deny > confirm > allow。
 * read_only 下额外拒绝重定向、后台、unsafe construct、敏感 env 与禁用程序；
 * allow 为空时拒绝一切命令。
 */
export function evaluateCommandPolicy(input: EvaluateCommandPolicyInput): CommandDecision {
  const { policy, surface } = input;

  if (policy.mode === 'off') {
    return makeDecision('allow', 'policy_off', '命令策略已关闭', surface);
  }
  if (policy.mode === 'read_only' && (surface === 'session_send' || surface === 'ssh_sudo')) {
    return makeDecision(
      'deny',
      'policy_read_only',
      `read_only 模式不允许在 ${surface} 上执行命令`,
      surface,
    );
  }

  const context = scanContext(input.command);

  const denyHit = findRule(policy.deny, context);
  if (denyHit !== undefined) {
    return makeDecision('deny', 'policy_denied', commandRuleReason(denyHit), surface, denyHit.id);
  }

  if (policy.mode === 'read_only') {
    const structural = readOnlyStructuralDeny(input, context);
    if (structural !== undefined) return structural;
  }

  const confirmHit = findRule(policy.confirm, context);
  if (confirmHit !== undefined) {
    return makeDecision(
      'confirm',
      'policy_confirm',
      `需要确认：${commandRuleReason(confirmHit)}`,
      surface,
      confirmHit.id,
    );
  }

  if (policy.allow.length === 0) {
    if (policy.mode === 'read_only') {
      return makeDecision(
        'deny',
        'policy_read_only_allowlist_empty',
        'read_only 模式未配置 allow 规则，拒绝所有命令',
        surface,
      );
    }
    if (context.rawSegments.length === 0) {
      return makeDecision('deny', 'policy_not_allowed', '空命令不在允许范围内', surface);
    }
    return makeDecision('allow', 'policy_allowed', '未配置 allow 规则，默认放行', surface);
  }

  if (context.rawSegments.length === 0) {
    return makeDecision('deny', 'policy_not_allowed', '空命令不在允许范围内', surface);
  }

  for (const segment of context.rawSegments) {
    if (!segmentMatchesAny(policy.allow, segment)) {
      return makeDecision(
        'deny',
        'policy_not_allowed',
        `片段不在 allow 规则内：${segment.text}`,
        surface,
      );
    }
  }

  return makeDecision('allow', 'policy_allowed', '命令命中 allow 规则', surface);
}

function usageError(
  code: string,
  message: string,
  details?: Record<string, unknown>,
): UsageError {
  const error = new UsageError(message, { code });
  if (details !== undefined) {
    (error as UsageError & { details?: Record<string, unknown> }).details = details;
  }
  return error;
}

/**
 * 断言策略结论为 allow；否则抛出带 code / details 的 UsageError（归类为 Policy）。
 */
export function assertCommandPolicy(decision: CommandDecision): void {
  if (decision.action === 'allow') return;
  throw usageError(decision.code, decision.reason, {
    action: decision.action,
    code: decision.code,
    ruleId: decision.ruleId,
    surface: decision.surface,
    reason: decision.reason,
  });
}

function compileSudoRules(sided: 'allow' | 'deny', specs: readonly string[]): CommandRule[] {
  return specs.map((spec, index) => parseRule(spec, 'sudo', `sudo:${sided}:${index}`));
}

/**
 * sudo 策略：先 deny 后 allow。mode=off 或上层策略为 read_only 时一律拒绝。
 * sudo.allow 为空表示默认放行（仍受 deny 约束）。
 */
export function evaluateSudoPolicy(input: EvaluateSudoPolicyInput): CommandDecision {
  const { sudo, surface } = input;
  if (input.policyMode === 'read_only') {
    return makeDecision('deny', 'policy_read_only', 'read_only 模式禁止使用 sudo', surface);
  }
  if (sudo.mode === 'off') {
    return makeDecision('deny', 'sudo_disabled', 'sudo 已在配置中关闭', surface);
  }

  const context = scanContext(input.command);
  // 加载期已预编译（defaultsFor）；直接构造的 sudo 对象才回退到按字符串解析。
  const denyRules = sudo.denyRules ?? compileSudoRules('deny', sudo.deny);
  const denyHit = findRule(denyRules, context);
  if (denyHit !== undefined) {
    return makeDecision('deny', 'policy_denied', commandRuleReason(denyHit), surface, denyHit.id);
  }

  const allowRules = sudo.allowRules ?? compileSudoRules('allow', sudo.allow);
  if (allowRules.length === 0) {
    return makeDecision('allow', 'policy_allowed', 'sudo 命令未配置 allow 规则，默认放行', surface);
  }
  if (context.rawSegments.length === 0) {
    return makeDecision('deny', 'policy_not_allowed', '空命令不在 sudo 允许范围内', surface);
  }
  for (const segment of context.rawSegments) {
    if (!segmentMatchesAny(allowRules, segment)) {
      return makeDecision(
        'deny',
        'policy_not_allowed',
        `sudo 片段不在 allow 规则内：${segment.text}`,
        surface,
      );
    }
  }
  return makeDecision('allow', 'policy_allowed', 'sudo 命令命中 allow 规则', surface);
}
