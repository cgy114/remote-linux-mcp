import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  assertRemoteCwd,
  assertRemoteSize,
  buildBashScript,
  buildExecCommand,
  DEFAULT_EXEC_LIMITS,
  encodeScript,
  MAX_COMMAND_BYTES,
  MAX_STDIN_BYTES,
  renderCwd,
  renderEnvExports,
  validateCwd,
  validateExecInput,
  wrapPayload,
  type ExecCommandInput,
} from '../../src/policy/remote-command.js';
import { hasLoneSurrogate } from '../../src/policy/shell.js';

function codeOf(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (e) {
    return (e as { code?: string }).code ?? 'NO_CODE';
  }
  return undefined;
}

const LIMITS = DEFAULT_EXEC_LIMITS;

function input(overrides: Partial<ExecCommandInput> = {}): ExecCommandInput {
  return { command: 'echo hi', cwd: '~', limits: LIMITS, ...overrides };
}

/** 解码 payload：普通字符按单字节，`\xHH` 按十六进制字节。 */
function decodePayload(payload: string): Buffer {
  const out: number[] = [];
  for (let i = 0; i < payload.length; ) {
    if (payload[i] === '\\' && payload[i + 1] === 'x') {
      out.push(Number.parseInt(payload.slice(i + 2, i + 4), 16));
      i += 4;
    } else {
      out.push(payload.charCodeAt(i));
      i += 1;
    }
  }
  return Buffer.from(out);
}

describe('assertRemoteCwd', () => {
  it('accepts absolute, "~" and "~/..." paths', () => {
    for (const ok of ['/', '~', '~/', '/srv/app', '~/a b', `/${'a'.repeat(4095)}`]) {
      expect(assertRemoteCwd(ok)).toBe(ok);
    }
  });

  it('rejects relative, empty, ~user, control chars and over-length', () => {
    const bad = [
      'rel/path',
      '',
      '~user',
      '~user/x',
      '~root',
      '/a\nb',
      '/a\rb',
      '/a\u0000b',
      `/${'a'.repeat(4096)}`,
      `/${String.fromCharCode(0xd800)}`,
    ];
    for (const v of bad) {
      expect(codeOf(() => assertRemoteCwd(v))).toBe('invalid_cwd');
    }
  });
});

describe('size constants', () => {
  it('exports the single source of truth for command and stdin limits', () => {
    expect(MAX_COMMAND_BYTES).toBe(16 * 1024);
    expect(MAX_STDIN_BYTES).toBe(1024 * 1024);
    expect(DEFAULT_EXEC_LIMITS.maxRemoteUtf8).toBe(MAX_STDIN_BYTES);
  });
});

describe('validateCwd', () => {
  it('accepts and returns a valid remote cwd', () => {
    expect(validateCwd('/srv/app')).toBe('/srv/app');
    expect(validateCwd('~')).toBe('~');
  });

  it('rejects invalid cwd with invalid_cwd', () => {
    expect(codeOf(() => validateCwd('relative'))).toBe('invalid_cwd');
    expect(codeOf(() => validateCwd('~user'))).toBe('invalid_cwd');
  });
});

describe('renderCwd', () => {
  it.each([
    ['~', '"$HOME"'],
    ['~/proj', '"$HOME"' + "'/proj'"],
    ['/srv/app', "'/srv/app'"],
    ['/tmp/a b', "'/tmp/a b'"],
    ["/tmp/a'b", "'/tmp/a'\\''b'"],
    ['/tmp/$(rm -rf /)', "'/tmp/$(rm -rf /)'"],
  ])('renders %j as %j', (cwd, expected) => {
    expect(renderCwd(cwd)).toBe(expected);
  });

  it('rejects ~user', () => {
    expect(codeOf(() => renderCwd('~user'))).toBe('invalid_cwd');
  });
});

describe('renderEnvExports', () => {
  it('sorts keys and single-quotes values', () => {
    expect(renderEnvExports({ B: '2', A: "it's" })).toEqual([
      "export A='it'\\''s'",
      "export B='2'",
    ]);
  });

  it('returns no lines for undefined', () => {
    expect(renderEnvExports(undefined)).toEqual([]);
  });

  it('rejects invalid and forbidden names', () => {
    expect(codeOf(() => renderEnvExports({ '1BAD': 'x' }))).toBe('invalid_env');
    expect(codeOf(() => renderEnvExports({ ['__proto__']: 'x' }))).toBe('invalid_env');
    expect(codeOf(() => renderEnvExports({ constructor: 'x' }))).toBe('invalid_env');
    expect(codeOf(() => renderEnvExports({ prototype: 'x' }))).toBe('invalid_env');
  });

  it('rejects NUL in a value', () => {
    expect(codeOf(() => renderEnvExports({ A: 'a\u0000b' }))).toBe('invalid_env');
  });
});

describe('validateExecInput', () => {
  it('accepts a normal input', () => {
    expect(() => validateExecInput(input())).not.toThrow();
  });

  it('rejects an empty, NUL-containing or lone-surrogate command', () => {
    expect(codeOf(() => validateExecInput(input({ command: '' })))).toBe('invalid_command');
    expect(codeOf(() => validateExecInput(input({ command: 'a\u0000b' })))).toBe('invalid_command');
    expect(
      codeOf(() =>
        validateExecInput(input({ command: `echo ${String.fromCharCode(0xd800)}` })),
      ),
    ).toBe('invalid_command');
  });

  it('rejects a command above 16384 UTF-8 bytes', () => {
    expect(codeOf(() => validateExecInput(input({ command: 'a'.repeat(16 * 1024 + 1) })))).toBe(
      'command_too_large',
    );
    expect(() => validateExecInput(input({ command: 'a'.repeat(16 * 1024) }))).not.toThrow();
  });

  it('rejects invalid stdin content and declared sizes', () => {
    expect(codeOf(() => validateExecInput(input({ stdin: 'a\u0000b' })))).toBe('invalid_stdin');
    expect(codeOf(() => validateExecInput(input({ stdin: Buffer.from([0x61, 0x00]) })))).toBe(
      'invalid_stdin',
    );
    expect(
      codeOf(() => validateExecInput(input({ stdin: 'a'.repeat(1024 * 1024 + 1) }))),
    ).toBe('invalid_stdin');
    expect(codeOf(() => validateExecInput(input({ stdinBytes: -1 })))).toBe('invalid_stdin');
    expect(codeOf(() => validateExecInput(input({ stdinBytes: 1.5 })))).toBe('invalid_stdin');
    expect(
      codeOf(() => validateExecInput(input({ stdinBytes: 1024 * 1024 + 1 }))),
    ).toBe('invalid_stdin');
  });

  it('rejects bad env keys, values, counts and total size', () => {
    expect(codeOf(() => validateExecInput(input({ env: { '1BAD': 'x' } })))).toBe('invalid_env');
    expect(codeOf(() => validateExecInput(input({ env: { A: 'a\u0000b' } })))).toBe('invalid_env');
    expect(
      codeOf(() => validateExecInput(input({ env: { A: 1 as unknown as string } }))),
    ).toBe('invalid_env');
    const many = Object.fromEntries(
      Array.from({ length: 65 }, (_, i) => [`K${i}`, 'x'] as const),
    );
    expect(codeOf(() => validateExecInput(input({ env: many })))).toBe('invalid_env');
    expect(
      codeOf(() => validateExecInput(input({ env: { BOMB: 'x'.repeat(17 * 1024) } }))),
    ).toBe('invalid_env');
  });

  it('rejects an invalid cwd', () => {
    expect(codeOf(() => validateExecInput(input({ cwd: '~user' })))).toBe('invalid_cwd');
    expect(codeOf(() => validateExecInput(input({ cwd: 'relative' })))).toBe('invalid_cwd');
  });

  it('skips cwd validation entirely when cwd is omitted', () => {
    expect(() => validateExecInput({ command: 'echo hi' })).not.toThrow();
    expect(() => validateExecInput({ command: 'echo hi', env: { A: '1' } })).not.toThrow();
  });
});

describe('buildBashScript', () => {
  it('puts env lines first, then cd, then the command after a newline', () => {
    expect(
      buildBashScript({ cwdExpr: '"$HOME"', envLines: ["export A='1'"], command: 'echo hi' }),
    ).toBe(`export A='1'\nbuiltin cd -- "$HOME" || exit 125\necho hi`);
  });

  it('ensures a newline before the command even with no env lines', () => {
    expect(buildBashScript({ cwdExpr: "'/srv'", envLines: [], command: 'pwd' })).toBe(
      `builtin cd -- '/srv' || exit 125\npwd`,
    );
  });
});

describe('encodeScript', () => {
  it('keeps ordinary printable ASCII unchanged', () => {
    expect(encodeScript('abc 123 ~/x')).toBe('abc 123 ~/x');
  });

  it('escapes quotes, dollar, backtick, backslash and bang', () => {
    expect(encodeScript(`a'b"c$d\`e\\f!g`)).toBe(
      'a\\x27b\\x22c\\x24d\\x60e\\x5Cf\\x21g',
    );
  });

  it('escapes control bytes and non-ASCII UTF-8', () => {
    expect(encodeScript('a\n\t')).toBe('a\\x0A\\x09');
    expect(encodeScript('中')).toBe('\\xE4\\xB8\\xAD');
    expect(encodeScript('😀')).toBe('\\xF0\\x9F\\x98\\x80');
  });

  it('never emits raw forbidden shell characters', () => {
    const payload = encodeScript(`'"$\\\`!`);
    expect(payload).toBe('\\x27\\x22\\x24\\x5C\\x60\\x21');
  });
});

describe('wrapPayload', () => {
  it('wraps the escaped payload for /bin/bash -lc', () => {
    const payload = encodeScript('echo hi\n');
    const remote = wrapPayload(payload);
    expect(remote).toBe(`/bin/bash -lc 'eval "$(printf %b "${payload}")"'`);
  });

  it('keeps the payload inside a single POSIX single-quoted word', () => {
    const payload = encodeScript("a'b");
    const remote = wrapPayload(payload);
    expect(remote).not.toContain("''");
    expect(remote.startsWith('/bin/bash -lc ')).toBe(true);
    expect(remote.endsWith(`"`)).toBe(false);
  });
});

describe('buildExecCommand', () => {
  it('renders every plan field', () => {
    const plan = buildExecCommand({
      command: 'echo hi',
      cwd: '~/proj',
      env: { B: '2', A: '1' },
      stdin: 'hello',
      limits: LIMITS,
    });
    expect(plan.commandSha256).toBe(createHash('sha256').update('echo hi').digest('hex'));
    expect(plan.commandBytes).toBe(7);
    expect(plan.cwd).toBe('~/proj');
    expect(plan.envKeys).toEqual(['A', 'B']);
    expect(plan.stdinBytes).toBe(5);
    expect(plan.bashScript).toBe(
      `export A='1'\nexport B='2'\nbuiltin cd -- "$HOME"'/proj' || exit 125\necho hi`,
    );
    expect(plan.payload).toBe(encodeScript(plan.bashScript));
    expect(plan.remoteCommand).toBe(wrapPayload(plan.payload));
    expect(plan.remoteCommand.startsWith('/bin/bash -lc ')).toBe(true);
  });

  it('records declared stdin bytes when no content is supplied', () => {
    expect(buildExecCommand(input({ stdinBytes: 42 })).stdinBytes).toBe(42);
    expect(buildExecCommand(input()).stdinBytes).toBe(0);
  });

  it('enforces the final remote size limits', () => {
    expect(
      codeOf(() =>
        buildExecCommand(input({ limits: { maxRemoteUtf16: 10, maxRemoteUtf8: 1024 } })),
      ),
    ).toBe('command_too_large');
    expect(
      codeOf(() =>
        buildExecCommand(input({ limits: { maxRemoteUtf16: 100_000, maxRemoteUtf8: 10 } })),
      ),
    ).toBe('command_too_large');
  });
});

describe('assertRemoteSize', () => {
  it('accepts within both limits and rejects either overflow', () => {
    expect(() => assertRemoteSize('abc', { maxRemoteUtf16: 3, maxRemoteUtf8: 3 })).not.toThrow();
    expect(() =>
      assertRemoteSize('abcd', { maxRemoteUtf16: 3, maxRemoteUtf8: 100 }),
    ).toThrow();
    expect(() =>
      assertRemoteSize('中', { maxRemoteUtf16: 1, maxRemoteUtf8: 2 }),
    ).toThrow();
  });
});

const wellFormedNoNul = fc
  .string({ minLength: 0, maxLength: 200 })
  .filter((s) => !s.includes('\u0000') && !hasLoneSurrogate(s));

/** payload 只允许：普通可打印 ASCII（不含引号/$/反引号/!），或 \xHH 转义。 */
function isEncodedPayload(payload: string): boolean {
  for (let i = 0; i < payload.length; i++) {
    const ch = payload[i] as string;
    if (ch === '\\') {
      if (!/^\\x[0-9A-F]{2}$/.test(payload.slice(i, i + 4))) return false;
      i += 3;
      continue;
    }
    const code = payload.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) return false;
    if (`'"$\`!`.includes(ch)) return false;
  }
  return true;
}

describe('encodeScript properties', () => {
  it('produces only printable ASCII plus \\xHH and round-trips UTF-8 bytes', () => {
    fc.assert(
      fc.property(wellFormedNoNul, (script) => {
        const payload = encodeScript(script);
        expect(isEncodedPayload(payload)).toBe(true);
        expect(decodePayload(payload)).toEqual(Buffer.from(script, 'utf8'));
      }),
      { numRuns: 300 },
    );
  });
});

// 探测 bash 是否可用，并记录其 `$OSTYPE`：Windows 上可能解析到 WSL（linux-gnu）
// 或 Cygwin/MSYS（cygwin、msys），两者能读取的脚本路径形式不同。
const bashEnvironment = (() => {
  try {
    const r = spawnSync('bash', ['-c', 'printf "%s|%s" ok "$OSTYPE"'], {
      encoding: 'utf8',
      timeout: 15_000,
    });
    if (r.error !== undefined || r.status !== 0) return undefined;
    const [ok, ostype = ''] = (r.stdout ?? '').split('|');
    return ok === 'ok' ? ostype : undefined;
  } catch {
    return undefined;
  }
})();
const bashAvailable = bashEnvironment !== undefined;

/** 把临时脚本路径转成该 bash 能读取的形式：WSL 需要 /mnt/<drive>/...；Cygwin/MSYS 接受 C:/...。 */
function bashScriptPath(winPath: string, ostype: string): string {
  if (process.platform !== 'win32') return winPath;
  const slashPath = winPath.replace(/\\/g, '/');
  if (ostype.startsWith('linux')) {
    return slashPath.replace(
      /^([A-Za-z]):\//,
      (_match, drive: string) => `/mnt/${drive.toLowerCase()}/`,
    );
  }
  return slashPath;
}

// Windows 上 `bash` 可能解析到 WSL 启动器：`bash -c <script>` 会在进程创建层
// 丢掉脚本里的 `$p`，导致输出为空。因此改为「临时脚本文件 + stdin 批量输入」，
// 完全避开命令行引号问题。脚本路径按 bash 类型转换（WSL -> /mnt/c/...），且不设
// cwd：WSL 会把启动时的 cwd 当作自身工作目录并持有目录句柄，导致临时目录删不掉。
// 单次 spawn 处理全部样本（每行一个 payload，payload 不含换行/NUL 且不含单引号）。
describe('encodeScript differential vs bash printf %b', () => {
  it.skipIf(!bashAvailable)(
    'matches bash output for arbitrary text in a single batch spawn',
    { timeout: 60_000 },
    () => {
      const samples = fc.sample(wellFormedNoNul, { numRuns: 40 });
      const payloads = samples.map((script) => encodeScript(script));

      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rm-bash-diff-'));
      try {
        const script = [
          'while IFS= read -r p; do',
          `  printf %b "$p" | od -An -v -tx1 | tr -d '[:space:]'`,
          `  printf '\\n'`,
          'done',
          '',
        ].join('\n');
        const localScriptPath = path.join(dir, 'diff.sh');
        const scriptPath = bashScriptPath(localScriptPath, bashEnvironment ?? '');
        fs.writeFileSync(localScriptPath, script, 'utf8');

        const started = Date.now();
        const r = spawnSync('bash', [scriptPath], {
          input: `${payloads.join('\n')}\n`,
          maxBuffer: 16 * 1024 * 1024,
          timeout: 60_000,
          encoding: 'utf8',
        });
        const elapsedMs = Date.now() - started;
        console.log(
          `[bash-diff] ${samples.length} samples in ${elapsedMs}ms (1 bash spawn, script file + stdin)`,
        );

        expect(r.error).toBeUndefined();
        expect(r.status, `bash stderr: ${r.stderr}`).toBe(0);

        const lines = r.stdout.split('\n');
        if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
        expect(lines).toHaveLength(samples.length);

        samples.forEach((scriptText, i) => {
          // od -tx1 输出小写、tr 已去掉空白；按实际格式归一化后再比对。
          const actualHex = (lines[i] as string).trim().toLowerCase();
          const expectedHex = Buffer.from(scriptText, 'utf8').toString('hex').toLowerCase();
          expect(actualHex, `sample #${i} ${JSON.stringify(scriptText)}`).toBe(expectedHex);
        });
      } finally {
        // 防御杀软扫描等外部句柄：Windows 上偶发 EPERM/EBUSY，按 maxRetries 重试。
        fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
      }
    },
  );
});
