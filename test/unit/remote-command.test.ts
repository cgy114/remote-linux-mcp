import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
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

const bashAvailable = (() => {
  try {
    const r = spawnSync('bash', ['-c', 'printf ok']);
    return r.error === undefined && r.status === 0 && r.stdout.toString() === 'ok';
  } catch {
    return false;
  }
})();

// Windows 上 `bash` 可能解析到 WSL，单次 spawn 约 1.5–2s；因此批量：一次 spawn
// 处理全部样本（每行一个 payload，payload 不含换行/NUL 且不含单引号），输出 hex 逐条比对。
describe('encodeScript differential vs bash printf %b', () => {
  it.skipIf(!bashAvailable)(
    'matches bash output for arbitrary text in a single batch spawn',
    { timeout: 60_000 },
    () => {
      const samples = fc.sample(wellFormedNoNul, { numRuns: 40 });
      const payloads = samples.map((script) => encodeScript(script));
      const script = `while IFS= read -r p; do printf %b "$p" | od -An -v -tx1 | tr -d '[:space:]'; printf '\\n'; done`;

      const started = Date.now();
      const r = spawnSync('bash', ['-c', script], {
        input: `${payloads.join('\n')}\n`,
        maxBuffer: 16 * 1024 * 1024,
      });
      const elapsedMs = Date.now() - started;
      console.log(`[bash-diff] ${samples.length} samples in ${elapsedMs}ms (1 bash spawn)`);

      expect(r.status).toBe(0);
      const lines = r.stdout.toString('utf8').split('\n');
      while (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
      expect(lines).toHaveLength(samples.length);

      samples.forEach((scriptText, i) => {
        const actual = Buffer.from(lines[i] as string, 'hex');
        expect(actual, `sample #${i} ${JSON.stringify(scriptText)}`).toEqual(
          Buffer.from(scriptText, 'utf8'),
        );
      });
    },
  );
});
