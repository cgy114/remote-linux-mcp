/**
 * 命令扫描：仅用于命令策略的 deny / allow 匹配，不执行任何命令。
 *
 * 这里的解析刻意保守：宁可把可疑输入标记为 unsafe，也不假设它是安全的。
 */

export interface CommandSegment {
  /** 去掉首尾空白后的原始片段。 */
  text: string;
  /** 结束该片段的分隔符（`;`、`&&`、`||`、`|`、`&`、`\n` 或空串）。 */
  separator: string;
  /** 未闭合引号、命令替换、反引号、进程替换、函数定义等。 */
  unsafe: boolean;
}

const ENV_ASSIGN_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;
const FUNC_DEF_RE =
  /(?:^|[\s;&|])(?:function\s+[A-Za-z_][A-Za-z0-9_]*\s*\{|[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\)\s*\{)/;
const SHELL_CONTROL_WORDS: ReadonlySet<string> = new Set([
  'eval',
  'source',
  '.',
  'alias',
  'set',
  'export',
  'unset',
  'trap',
]);

/**
 * 极简 shell 词法：按空白切分，去掉引号与转义反斜杠。
 * 不做变量展开；`$IFS` 由 normalizeSkeleton 负责。
 */
export function tokenize(input: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let started = false;
  let inSingle = false;
  let inDouble = false;

  const push = (): void => {
    if (started) tokens.push(current);
    current = '';
    started = false;
  };

  for (let i = 0; i < input.length; i++) {
    const ch = input[i] ?? '';
    if (inSingle) {
      if (ch === "'") inSingle = false;
      else current += ch;
      continue;
    }
    if (inDouble) {
      if (ch === '\\') {
        const next = input[i + 1];
        if (next !== undefined && '"\\$`\n'.includes(next)) {
          current += next;
          i++;
        } else {
          current += ch;
        }
        continue;
      }
      if (ch === '"') inDouble = false;
      else current += ch;
      continue;
    }
    if (ch === '\\') {
      const next = input[i + 1];
      if (next !== undefined) {
        current += next;
        i++;
      } else {
        current += ch;
      }
      started = true;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      started = true;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      started = true;
      continue;
    }
    if (/\s/.test(ch)) {
      push();
      continue;
    }
    current += ch;
    started = true;
  }
  push();
  return tokens;
}

/**
 * 为 deny 扫描生成“骨架”：
 * - 去掉 `\` 续行与其他转义反斜杠（`\rm` -> `rm`）
 * - 去掉空引号对（`r''m` -> `rm`，`r""m` -> `rm`）
 * - `$IFS` / `${IFS}` -> 空格
 * - 折叠水平空白，保留换行作为片段分隔
 *
 * 该结果绝不能用于执行，只用于匹配 deny 规则。
 */
export function normalizeSkeleton(command: string): string {
  let out = command.replace(/\\\r?\n/g, '');
  out = out.replace(/\\([^\n])/g, '$1');
  out = out.replace(/(['"])\1/g, '');
  out = out.replace(/\$\{IFS\}|\$IFS/g, ' ');
  out = out.replace(/[ \t\r\f\v]+/g, ' ');
  out = out.replace(/\n+/g, '\n');
  return out.trim();
}

/**
 * 引号感知地按 `;`、`&&`、`||`、`|`、`&`、换行切分命令。
 * 空片段被丢弃；未闭合引号、命令替换、反引号、进程替换、函数定义标记 unsafe。
 */
export function splitSegments(command: string): CommandSegment[] {
  const segments: CommandSegment[] = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;
  let unsafe = false;

  const push = (separator: string): void => {
    const text = current.trim();
    if (text.length > 0) segments.push({ text, separator, unsafe });
    current = '';
    unsafe = false;
  };

  for (let i = 0; i < command.length; i++) {
    const ch = command[i] ?? '';
    if (inSingle) {
      current += ch;
      if (ch === "'") inSingle = false;
      continue;
    }
    if (inDouble) {
      if (ch === '\\') {
        current += ch;
        const next = command[i + 1];
        if (next !== undefined) {
          current += next;
          i++;
        }
        continue;
      }
      if (ch === '"') inDouble = false;
      if (ch === '`' || (ch === '$' && command[i + 1] === '(')) unsafe = true;
      current += ch;
      continue;
    }
    if (ch === '\\') {
      current += ch;
      const next = command[i + 1];
      if (next !== undefined) {
        current += next;
        i++;
      }
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      current += ch;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      current += ch;
      continue;
    }
    if (ch === '`' || (ch === '$' && command[i + 1] === '(')) unsafe = true;
    if ((ch === '<' || ch === '>') && command[i + 1] === '(') unsafe = true;
    if (ch === ';') {
      push(';');
      continue;
    }
    if (ch === '&') {
      if (command[i + 1] === '&') {
        i++;
        push('&&');
      } else {
        push('&');
      }
      continue;
    }
    if (ch === '|') {
      if (command[i + 1] === '|') {
        i++;
        push('||');
      } else {
        push('|');
      }
      continue;
    }
    if (ch === '\n') {
      push('\n');
      continue;
    }
    current += ch;
  }

  if (inSingle || inDouble) unsafe = true;
  push('');

  for (const segment of segments) {
    if (FUNC_DEF_RE.test(segment.text)) segment.unsafe = true;
  }
  return segments;
}

/**
 * 返回片段的前 n 个“有效词”：去引号、跳过 `NAME=value` 环境赋值、
 * 剥离 `command` / `builtin` 包装（含其选项）。
 */
export function leadingWords(segment: string, n: number): string[] {
  if (n <= 0) return [];
  const tokens = tokenize(segment).filter((token) => token.length > 0);
  let index = 0;
  while (index < tokens.length && ENV_ASSIGN_RE.test(tokens[index] ?? '')) index++;
  while (index < tokens.length) {
    const word = tokens[index] ?? '';
    if (word === 'command' || word === 'builtin') {
      index++;
      while (index < tokens.length && (tokens[index] ?? '').startsWith('-')) index++;
      continue;
    }
    break;
  }
  return tokens.slice(index, index + n);
}

const SHELL_KEYWORDS = new Set([
  'if',
  'then',
  'else',
  'elif',
  'do',
  'while',
  'until',
  'for',
  'case',
  '!',
  '{',
  '(',
]);

/**
 * 去掉片段开头的环境赋值、`command`/`builtin` 包装、shell 关键字，
 * 仅用于 deny 扫描（不改变引号与其余内容）。
 */
export function stripLeadingNoise(text: string): string {
  let out = text;
  for (;;) {
    const before = out;
    out = out.replace(/^\s+/, '');
    out = out.replace(/^[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S*)\s+/, '');
    out = out.replace(/^(?:command|builtin)(?:\s+-[^\s]+)*\s+/, '');
    const keyword =
      /^(?:(?:if|then|else|elif|do|while|until|for|case)(?=\s|$)|[!{}(]|\$\()/.exec(out);
    if (keyword !== null) {
      out = out.slice(keyword[0].length).replace(/^\s+/, '');
    }
    if (out === before) return out;
  }
}

/** 引号感知地检测命令替换、反引号、进程替换、函数定义与破坏性内建。 */
export function hasUnsafeConstruct(segment: string): boolean {
  const segments = splitSegments(segment);
  if (segments.some((part) => part.unsafe)) return true;
  return segments.some((part) => {
    const first = leadingWords(part.text, 1)[0];
    return first !== undefined && SHELL_CONTROL_WORDS.has(first);
  });
}

/** 引号感知地检测输出/输入重定向（`<`、`>`、`<<`、`<<<`、`&>` 等）。 */
export function hasRedirection(segment: string): boolean {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i] ?? '';
    if (inSingle) {
      if (ch === "'") inSingle = false;
      continue;
    }
    if (inDouble) {
      if (ch === '\\') {
        i++;
        continue;
      }
      if (ch === '"') inDouble = false;
      continue;
    }
    if (ch === '\\') {
      i++;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      continue;
    }
    if (ch === '<' || ch === '>') return true;
  }
  return false;
}
