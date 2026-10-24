import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { renderCwd, renderEnvExports } from '../../src/policy/remote-command.js';
import { buildSessionBootstrap } from '../../src/policy/session.js';
import { createFrameParser, createNonce } from '../../src/session/frame.js';
import type { Frame, FrameEvent } from '../../src/session/types.js';

const NONCE = '0123456789abcdef0123456789abcdef';

function scriptOf(lines: string[]): string {
  return lines.join('\n');
}

const bashAvailable = (() => {
  try {
    const r = spawnSync('bash', ['-c', ':'], { timeout: 5000, windowsHide: true });
    return !r.error && r.status === 0;
  } catch {
    return false;
  }
})();

/** 用真实 bash 跑一遍 bootstrap，并通过协议行驱动命令，返回解析后的帧与用户输出。 */
function runBootstrap(protocol: string): {
  frames: Frame[];
  data: Buffer;
  status: number | null;
  stderr: string;
} {
  const script = scriptOf(
    buildSessionBootstrap({ nonce: NONCE, cwdExpr: renderCwd('~'), envLines: [] }),
  );
  const r = spawnSync('bash', ['--noprofile', '--norc', '-c', script], {
    input: protocol,
    timeout: 10_000,
    windowsHide: true,
  });
  const parser = createFrameParser(NONCE);
  const result = parser.push(r.stdout ?? Buffer.alloc(0));
  const events: FrameEvent[] = [...result.events, ...parser.flush()];
  return {
    frames: events
      .filter((event) => event.type === 'frame')
      .map((event) => (event as { frame: Frame }).frame),
    data: Buffer.concat(
      events.filter((event) => event.type === 'data').map((event) => (event as { buf: Buffer }).buf),
    ),
    status: r.status,
    stderr: (r.stderr ?? Buffer.alloc(0)).toString('utf8'),
  };
}

describe('buildSessionBootstrap', () => {
  const lines = buildSessionBootstrap({
    nonce: NONCE,
    cwdExpr: renderCwd('~/work'),
    envLines: renderEnvExports({ FOO: 'bar', PATH: '/usr/bin:/bin' }),
  });
  const script = scriptOf(lines);

  it('starts by disabling xtrace, then fd setup and stderr merge', () => {
    expect(lines[0]).toBe('builtin set +x');
    expect(lines[1]).toBe('exec 3>&1; exec 2>&1');
  });

  it('places sorted env exports before cd', () => {
    expect(lines.slice(2, 4)).toEqual([
      "export FOO='bar'",
      "export PATH='/usr/bin:/bin'",
    ]);
    expect(lines[4]).toBe(`builtin cd -- ${renderCwd('~/work')} || exit 125`);
  });

  it('includes a trap that restores fd1/fd2', () => {
    const trap = lines.find((line) => line.startsWith('trap '));
    expect(trap).toBeDefined();
    expect(trap).toContain('exec 1>&3 2>&3');
  });

  it('announces readiness on fd3 with RS/US framing', () => {
    expect(lines).toContain(`builtin printf '\\036RMCP%s:RDY\\037' "$RMCP_NONCE" >&3`);
  });

  it('wraps every command with B and E frames on fd3', () => {
    expect(lines).toContain(
      `  builtin printf '\\036RMCP%s:B:%s\\037' "$RMCP_NONCE" "$RMCP_SEQ" >&3`,
    );
    expect(lines).toContain(
      `  builtin printf '\\036RMCP%s:E:%s:%s\\037' "$RMCP_NONCE" "$RMCP_SEQ" "$RMCP_RC" >&3`,
    );
  });

  it('runs commands from encoded payloads with stdin detached', () => {
    expect(lines).toContain('  eval "$(builtin printf %b "$RMCP_PAYLOAD")" </dev/null');
    expect(script).toContain('IFS= read -r RMCP_LINE');
    expect(script).toContain('RMCP_SEQ=${RMCP_LINE%% *}');
    expect(script).toContain('RMCP_PAYLOAD=${RMCP_LINE#* }');
  });

  it('disables errexit around every command and re-anchors fds before E', () => {
    const evalIdx = lines.findIndex((line) => line.includes('eval "$(builtin printf %b'));
    expect(evalIdx).toBeGreaterThan(0);
    expect(lines[evalIdx - 1]).toBe('  set +e');
    expect(lines[evalIdx + 1]).toBe('  RMCP_RC=$?');
    expect(lines[evalIdx + 2]).toBe('  exec 1>&3 2>&3');
    expect(lines[evalIdx + 3]).toBe('  set +e');
    expect(lines[evalIdx + 4]).toBe('  builtin set +x');
    expect(lines[evalIdx + 5]).toContain('E:%s:%s');
  });

  it('disables xtrace at bootstrap start and before every frame write', () => {
    const whileIdx = lines.findIndex((line) => line.startsWith('while '));
    expect(lines[whileIdx + 1]).toBe('  builtin set +x');

    const frameLines = lines
      .map((line, index) => ({ line, index }))
      .filter(({ line }) => line.includes(':B:%s') || line.includes(':E:%s'));
    expect(frameLines).toHaveLength(2);
    for (const { index } of frameLines) {
      expect(lines[index - 1]).toBe('  builtin set +x');
    }
  });

  it('handles the Q close line by leaving the loop', () => {
    expect(lines).toContain('  case "$RMCP_SEQ" in');
    expect(lines).toContain('    Q) break ;;');
    expect(lines).toContain('  esac');
  });

  it('restores fds after the loop', () => {
    expect(lines.at(-1)).toBe('exec 1>&3 2>&3');
  });

  it('uses builtin printf everywhere and puts the nonce exactly once', () => {
    for (const line of lines) {
      if (line.includes('printf')) expect(line).toContain('builtin printf');
    }
    expect(script.split(NONCE)).toHaveLength(2);
  });

  it('contains no user command (payloads only arrive through stdin)', () => {
    const injected = 'rm -rf / --no-preserve-root';
    expect(script).not.toContain(injected);
    const withEnv = buildSessionBootstrap({
      nonce: NONCE,
      cwdExpr: renderCwd('~'),
      envLines: renderEnvExports({ SAFE: 'value' }),
    });
    expect(scriptOf(withEnv)).not.toContain(injected);
  });

  it('accepts an empty env block', () => {
    const bare = buildSessionBootstrap({ nonce: NONCE, cwdExpr: renderCwd('/'), envLines: [] });
    expect(bare).toHaveLength(24);
    expect(bare.every((line) => !line.startsWith('export '))).toBe(true);
  });

  it('works with a freshly generated nonce', () => {
    const nonce = createNonce();
    const fresh = buildSessionBootstrap({ nonce, cwdExpr: renderCwd('~'), envLines: [] });
    expect(scriptOf(fresh).split(nonce)).toHaveLength(2);
    expect(fresh.some((line) => line.includes(':RDY'))).toBe(true);
  });

  it('rejects invalid nonces', () => {
    for (const nonce of ['', 'abc', 'A'.repeat(32), 'g'.repeat(32), '0'.repeat(33)]) {
      expect(() => buildSessionBootstrap({ nonce, cwdExpr: '"$HOME"', envLines: [] })).toThrow(
        TypeError,
      );
    }
  });

  it('rejects multi-line or NUL-containing cwd expressions', () => {
    for (const cwdExpr of ['', 'a\nb', 'a\rb', 'a\u0000b']) {
      expect(() => buildSessionBootstrap({ nonce: NONCE, cwdExpr, envLines: [] })).toThrow(
        TypeError,
      );
    }
  });

  it('rejects env lines that are not generated exports', () => {
    expect(() =>
      buildSessionBootstrap({ nonce: NONCE, cwdExpr: '"$HOME"', envLines: ['FOO=bar'] }),
    ).toThrow(TypeError);
    expect(() =>
      buildSessionBootstrap({
        nonce: NONCE,
        cwdExpr: '"$HOME"',
        envLines: ['export A=\u0000'],
      }),
    ).toThrow(TypeError);
    expect(() =>
      buildSessionBootstrap({
        nonce: NONCE,
        cwdExpr: '"$HOME"',
        envLines: null as unknown as string[],
      }),
    ).toThrow(TypeError);
  });

  it.skipIf(!bashAvailable)('is syntactically valid bash', () => {
    const r = spawnSync('bash', ['-n', '-c', script], { timeout: 5000, windowsHide: true });
    expect(r.error).toBeUndefined();
    expect(r.status, r.stderr.toString()).toBe(0);
  });

  it.skipIf(!bashAvailable)('keeps the loop alive when a command enables errexit', () => {
    const run = runBootstrap('1 set -e\n2 false\n3 echo hello\nQ\n');
    expect(run.status, run.stderr).toBe(0);

    const ends = run.frames.filter(
      (frame): frame is Extract<Frame, { type: 'E' }> => frame.type === 'E',
    );
    // set -e 生效后，下一条 false 的 rc=1 仍应被上报，循环继续执行 seq=3。
    expect(ends).toEqual([
      { type: 'E', seq: 1, rc: 0 },
      { type: 'E', seq: 2, rc: 1 },
      { type: 'E', seq: 3, rc: 0 },
    ]);
    expect(run.data.toString()).toContain('hello\n');
  });

  it.skipIf(!bashAvailable)('keeps the nonce out of output when a command enables xtrace', () => {
    const run = runBootstrap('1 set -x\n2 echo hi\nQ\n');
    expect(run.status, run.stderr).toBe(0);

    // xtrace 模式下循环体/帧写前都会 `builtin set +x`；捕获数据不得出现 nonce。
    expect(run.data.toString()).not.toContain(NONCE);
    expect(run.data.toString()).toContain('hi\n');
    const ends = run.frames.filter(
      (frame): frame is Extract<Frame, { type: 'E' }> => frame.type === 'E',
    );
    expect(ends).toEqual([
      { type: 'E', seq: 1, rc: 0 },
      { type: 'E', seq: 2, rc: 0 },
    ]);
  });

  it.skipIf(!bashAvailable)('re-anchors stdout and stderr after a command redirects them', () => {
    const run = runBootstrap('1 exec >/tmp/x 2>&1\n2 echo hello\nQ\n');
    expect(run.status, run.stderr).toBe(0);

    const ends = run.frames.filter(
      (frame): frame is Extract<Frame, { type: 'E' }> => frame.type === 'E',
    );
    expect(ends).toEqual([
      { type: 'E', seq: 1, rc: 0 },
      { type: 'E', seq: 2, rc: 0 },
    ]);
    expect(run.data.toString()).toContain('hello\n');
  });
});
