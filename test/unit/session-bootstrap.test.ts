import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { renderCwd, renderEnvExports } from '../../src/policy/remote-command.js';
import { buildSessionBootstrap } from '../../src/policy/session.js';
import { createNonce } from '../../src/session/frame.js';

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

describe('buildSessionBootstrap', () => {
  const lines = buildSessionBootstrap({
    nonce: NONCE,
    cwdExpr: renderCwd('~/work'),
    envLines: renderEnvExports({ FOO: 'bar', PATH: '/usr/bin:/bin' }),
  });
  const script = scriptOf(lines);

  it('starts with fd setup and merges remote stderr into stdout', () => {
    expect(lines[0]).toBe('exec 3>&1; exec 2>&1');
  });

  it('places sorted env exports before cd', () => {
    expect(lines.slice(1, 3)).toEqual([
      "export FOO='bar'",
      "export PATH='/usr/bin:/bin'",
    ]);
    expect(lines[3]).toBe(`builtin cd -- ${renderCwd('~/work')} || exit 125`);
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
    expect(bare).toHaveLength(17);
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
});
