import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config/load.js';
import { resolvePaths } from '../../src/config/paths.js';
import { createLogger } from '../../src/log.js';
import { getSessionRegistry } from '../../src/session/registry.js';
import { sshExec } from '../../src/tools/ssh-exec.js';
import type { ToolContext } from '../../src/tools/common.js';
import { sessionClose } from '../../src/tools/session-close.js';
import { sessionList } from '../../src/tools/session-list.js';
import { sessionSend } from '../../src/tools/session-send.js';
import { sessionStart } from '../../src/tools/session-start.js';
import type { RemoteConfig } from '../../src/types.js';

const E2E = process.env.REMOTE_MCP_E2E === '1';
const ALIAS = process.env.REMOTE_MCP_E2E_ALIAS ?? 'orangepi';
const TEST_TIMEOUT_MS = 60_000;

interface ToolResultLike {
  isError?: boolean;
  content?: Array<{ type: string; text?: string }>;
  structuredContent?: unknown;
}

interface StartStructured {
  tool: string;
  session_id: string;
  host: string;
  destination: string;
  cwd: string;
  env_keys: string[];
  idle_timeout_ms: number;
}

interface SendStructured {
  tool: string;
  session_id: string;
  host: string;
  destination: string;
  exit_code: number;
  output: string;
  encoding: 'utf-8' | 'base64';
  bytes: number;
  truncated: boolean;
  duration_ms: number;
  queue_ms: number;
  session_queue_ms: number;
}

interface CloseStructured {
  tool: string;
  session_id: string;
  host: string;
  destination: string;
  exit_code: number | null;
  signal: string | null;
  graceful: boolean;
  killed: boolean;
  duration_ms: number;
}

interface ListStructured {
  tool: string;
  count: number;
  sessions: Array<{ session_id: string; state: string }>;
}

interface ErrorStructured {
  tool?: string;
  host?: string;
  error: { kind: string; code: string; message: string };
}

interface ExecStructured {
  exit_code: number | null;
  stdout: string;
  stderr: string;
  timed_out: boolean;
  stdout_bytes: number;
  stderr_bytes: number;
}

function structured<T>(result: ToolResultLike): T {
  return result.structuredContent as T;
}

function textOf(result: ToolResultLike): string {
  const first = result.content?.[0];
  return first !== undefined && first.text !== undefined ? first.text : JSON.stringify(result);
}

function errorOf(result: ToolResultLike): ErrorStructured['error'] {
  return structured<ErrorStructured>(result).error;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** 轮询直到 fn 返回非 undefined；超时抛出带标签的错误。 */
async function waitFor<T>(
  label: string,
  fn: () => Promise<T | undefined>,
  timeoutMs = 8_000,
): Promise<T> {
  const started = Date.now();
  let lastError: unknown;
  while (Date.now() - started < timeoutMs) {
    try {
      const value = await fn();
      if (value !== undefined) return value;
    } catch (err) {
      lastError = err;
    }
    await delay(100);
  }
  const suffix = lastError !== undefined ? `: ${String(lastError)}` : '';
  throw new Error(`timed out waiting for ${label}${suffix}`);
}

/**
 * P4 持久会话的真实主机 E2E。默认跳过；REMOTE_MCP_E2E=1 时直接调用
 * sessionStart/sessionSend/sessionClose/sessionList，覆盖状态持久、隔离、
 * 后台进程、超时、输出保真、容量上限与远端清理。
 */
describe.skipIf(!E2E)(`integration: persistent sessions on real host (${ALIAS})`, () => {
  let ctx: ToolContext;
  let config: RemoteConfig;
  let remoteHome: string | undefined;
  const openIds = new Set<string>();

  beforeAll(async () => {
    const paths = resolvePaths({ env: process.env });
    config = await loadConfig(paths);
    ctx = {
      paths,
      log: createLogger({ level: 'error' }),
      getConfig: async () => config,
    };
  }, 15_000);

  afterEach(async () => {
    for (const id of [...openIds]) {
      try {
        await sessionClose({ session_id: id }, ctx);
      } catch (err) {
        console.error(`[cleanup] session_close(${id}) failed: ${String(err)}`);
      }
      openIds.delete(id);
    }
  });

  afterAll(async () => {
    // 最后兜底：即使某个用例中途失败，也不把会话留给后续测试或远端。
    await getSessionRegistry().closeAll('test_teardown', 5_000);
  }, 15_000);

  async function startSession(
    input: Record<string, unknown> = {},
    track = true,
  ): Promise<StartStructured> {
    const result = await sessionStart({ host: ALIAS, ...input }, ctx);
    if (result.isError === true) {
      throw new Error(`session_start failed: ${textOf(result)}`);
    }
    const s = structured<StartStructured>(result);
    if (track) openIds.add(s.session_id);
    return s;
  }

  async function send(
    id: string,
    command: string,
    extra: { timeout_ms?: number; max_output_bytes?: number } = {},
  ): Promise<SendStructured> {
    const result = await sessionSend({ session_id: id, command, ...extra }, ctx);
    if (result.isError === true) {
      throw new Error(`session_send failed for ${JSON.stringify(command)}: ${textOf(result)}`);
    }
    return structured<SendStructured>(result);
  }

  async function close(id: string): Promise<CloseStructured> {
    const result = await sessionClose({ session_id: id }, ctx);
    openIds.delete(id);
    if (result.isError === true) {
      throw new Error(`session_close failed: ${textOf(result)}`);
    }
    return structured<CloseStructured>(result);
  }

  async function list(): Promise<ListStructured> {
    const result = await sessionList({}, ctx);
    if (result.isError === true) {
      throw new Error(`session_list failed: ${textOf(result)}`);
    }
    return structured<ListStructured>(result);
  }

  async function home(): Promise<string> {
    if (remoteHome === undefined) {
      const result = await sshExec(
        { host: ALIAS, command: 'printf %s "$HOME"', timeout_ms: 15_000 },
        ctx,
      );
      if (result.isError === true) {
        throw new Error(`failed to resolve remote HOME: ${textOf(result)}`);
      }
      remoteHome = structured<ExecStructured>(result).stdout;
      if (remoteHome === '') throw new Error('remote HOME is empty');
    }
    return remoteHome;
  }

  it(
    'start -> pwd -> close: returns a session id, pwd is the remote home, list empties',
    async () => {
      const started = await startSession();
      expect(started.tool).toBe('session_start');
      expect(started.session_id).toMatch(/^sess_[0-9a-f]{32}$/);
      expect(started.host).toBe(ALIAS);
      expect(started.cwd).toBe('~');

      const pwd = await send(started.session_id, 'pwd');
      expect(pwd.exit_code).toBe(0);
      expect(pwd.encoding).toBe('utf-8');
      expect(pwd.truncated).toBe(false);
      expect(pwd.output.trim()).toBe(await home());
      expect(pwd.bytes).toBeGreaterThan(0);

      const closed = await close(started.session_id);
      expect(closed.session_id).toBe(started.session_id);
      expect(typeof closed.graceful).toBe('boolean');
      expect(typeof closed.killed).toBe('boolean');

      const after = await list();
      expect(after.count).toBe(0);
      expect(after.sessions).toEqual([]);
    },
    TEST_TIMEOUT_MS,
  );

  it(
    'keeps cwd and env across commands in one session',
    async () => {
      const started = await startSession();

      const cd = await send(started.session_id, 'cd /tmp && pwd');
      expect(cd.exit_code).toBe(0);
      expect(cd.output.trim()).toBe('/tmp');

      const exported = await send(
        started.session_id,
        'export RMCP_XYZ=persist; printf %s "$RMCP_XYZ"',
      );
      expect(exported.exit_code).toBe(0);
      expect(exported.output).toBe('persist');

      const stillSet = await send(started.session_id, 'printf %s "$RMCP_XYZ"');
      expect(stillSet.exit_code).toBe(0);
      expect(stillSet.output).toBe('persist');

      const stillTmp = await send(started.session_id, 'pwd');
      expect(stillTmp.exit_code).toBe(0);
      expect(stillTmp.output.trim()).toBe('/tmp');

      await close(started.session_id);
      expect((await list()).count).toBe(0);
    },
    TEST_TIMEOUT_MS,
  );

  it(
    'isolates two sessions from each other and closing one leaves the other intact',
    async () => {
      const homeDir = await home();
      const a = await startSession();
      const b = await startSession();

      const aCd = await send(a.session_id, 'cd /tmp; export RMCP_ISO=session-a');
      expect(aCd.exit_code).toBe(0);
      const aPwd = await send(a.session_id, 'pwd');
      expect(aPwd.output.trim()).toBe('/tmp');
      const aVar = await send(a.session_id, 'printf %s "$RMCP_ISO"');
      expect(aVar.output).toBe('session-a');

      const bPwd = await send(b.session_id, 'pwd');
      expect(bPwd.output.trim()).toBe(homeDir);
      const bVar = await send(b.session_id, 'printf "[%s]" "${RMCP_ISO-}"');
      expect(bVar.output).toBe('[]');

      await close(a.session_id);

      const bPwdAfter = await send(b.session_id, 'pwd');
      expect(bPwdAfter.exit_code).toBe(0);
      expect(bPwdAfter.output.trim()).toBe(homeDir);
      const bVarAfter = await send(b.session_id, 'printf "[%s]" "${RMCP_ISO-}"');
      expect(bVarAfter.output).toBe('[]');

      const remaining = await list();
      expect(remaining.count).toBe(1);
      expect(remaining.sessions[0]?.session_id).toBe(b.session_id);

      await close(b.session_id);
      expect((await list()).count).toBe(0);
    },
    TEST_TIMEOUT_MS,
  );

  it(
    'keeps background jobs addressable and terminates them before close',
    async () => {
      const started = await startSession();

      const spawn = await send(started.session_id, 'sleep 300 & echo $!');
      expect(spawn.exit_code).toBe(0);
      const pidText = spawn.output.trim();
      expect(pidText).toMatch(/^\d+$/);
      const pid = Number(pidText);

      const alive = await send(
        started.session_id,
        `if kill -0 ${pid} 2>/dev/null; then echo alive; else echo gone; fi`,
      );
      expect(alive.exit_code).toBe(0);
      expect(alive.output.trim()).toBe('alive');

      const kill = await send(started.session_id, `kill ${pid}`);
      expect(kill.exit_code).toBe(0);

      await waitFor(
        'background process to exit after kill',
        async () => {
          const check = await send(
            started.session_id,
            `if kill -0 ${pid} 2>/dev/null; then echo alive; else echo gone; fi`,
          );
          return check.output.trim() === 'gone' ? true : undefined;
        },
        5_000,
      );

      await close(started.session_id);

      // 会话关闭后用一次性 ssh_exec 确认远端已无该 pid。
      await waitFor(
        'background process to be gone after close',
        async () => {
          const check = await sshExec(
            {
              host: ALIAS,
              command: `if kill -0 ${pid} 2>/dev/null; then echo alive; else echo gone; fi`,
              timeout_ms: 10_000,
            },
            ctx,
          );
          if (check.isError === true) return undefined;
          return structured<ExecStructured>(check).stdout.trim() === 'gone' ? true : undefined;
        },
        5_000,
      );
    },
    TEST_TIMEOUT_MS,
  );

  it(
    'times out a command, self-removes the session and frees the slot immediately',
    async () => {
      const started = await startSession();
      const id = started.session_id;

      const timedOut = await sessionSend(
        { session_id: id, command: 'sleep 30', timeout_ms: 1_500 },
        ctx,
      );
      expect(timedOut.isError).toBe(true);
      const err = errorOf(timedOut);
      expect(err.kind).toBe('Timeout');
      expect(err.code).toBe('session_timeout');

      // 超时即自关闭并自动从登记簿移除：无需显式 close，list 中不再有该 id。
      await waitFor(
        'session to leave session_list after timeout',
        async () => {
          const current = await list();
          return current.sessions.some((s) => s.session_id === id) ? undefined : true;
        },
        8_000,
      );
      openIds.delete(id);

      // 后续 send 必须被拒绝（条目已自移除，通常为 unknown_session）。
      const later = await sessionSend({ session_id: id, command: 'echo still-there' }, ctx);
      expect(later.isError).toBe(true);
      expect(['session_closed', 'unknown_session']).toContain(errorOf(later).code);

      // 无 tombstone：对已自移除的会话再 close 得到 unknown_session。
      const closed = await sessionClose({ session_id: id }, ctx);
      expect(closed.isError).toBe(true);
      expect(errorOf(closed).code).toBe('unknown_session');

      // 名额已释放：可以立即新建一个会话并正常执行。
      const replacement = await startSession();
      expect(replacement.session_id).not.toBe(id);
      const pong = await send(replacement.session_id, 'printf %s pong');
      expect(pong.exit_code).toBe(0);
      expect(pong.output).toBe('pong');

      await close(replacement.session_id);
      expect((await list()).count).toBe(0);
    },
    TEST_TIMEOUT_MS,
  );

  it(
    'frees a per-host slot as soon as a session times out (no explicit close needed)',
    async () => {
      // 占满每目标 2 个名额：keeper 保持存活，victim 因超时自关闭。
      const keeper = await startSession();
      const victim = await startSession();

      const timedOut = await sessionSend(
        { session_id: victim.session_id, command: 'sleep 30', timeout_ms: 1_500 },
        ctx,
      );
      expect(timedOut.isError).toBe(true);
      expect(errorOf(timedOut).code).toBe('session_timeout');

      await waitFor(
        'timed-out session to leave the registry',
        async () => {
          const current = await list();
          return current.sessions.some((s) => s.session_id === victim.session_id)
            ? undefined
            : true;
        },
        8_000,
      );
      openIds.delete(victim.session_id);

      // 名额已释放：若未释放，这里会返回 too_many_sessions。
      const replacement = await startSession();
      const pong = await send(replacement.session_id, 'printf %s pong');
      expect(pong.output).toBe('pong');

      await close(keeper.session_id);
      await close(replacement.session_id);
      expect((await list()).count).toBe(0);
    },
    TEST_TIMEOUT_MS,
  );

  it(
    'preserves ANSI sequences, missing trailing newlines and large single-line output',
    async () => {
      const started = await startSession();

      const ansi = await send(started.session_id, "printf '\\033[31mred\\033[0m'");
      expect(ansi.exit_code).toBe(0);
      expect(ansi.output).toBe('\u001b[31mred\u001b[0m');
      expect(ansi.bytes).toBe(12);
      expect(ansi.truncated).toBe(false);

      const noNewline = await send(started.session_id, "printf 'no-trailing-newline'");
      expect(noNewline.exit_code).toBe(0);
      expect(noNewline.output).toBe('no-trailing-newline');
      expect(noNewline.bytes).toBe(Buffer.byteLength('no-trailing-newline', 'utf8'));

      const big = await send(
        started.session_id,
        "printf 'A'; head -c 999998 /dev/zero | tr '\\0' x; printf 'Z'",
      );
      expect(big.exit_code).toBe(0);
      expect(big.truncated).toBe(false);
      expect(big.bytes).toBe(1_000_000);
      expect(big.output.length).toBe(1_000_000);
      expect(big.output.startsWith('A')).toBe(true);
      expect(big.output.endsWith('Z')).toBe(true);

      // max_output_bytes 语义：超过上限时保留头尾、标记截断，bytes 仍是总字节数。
      const truncated = await send(
        started.session_id,
        "printf 'HEAD'; head -c 9992 /dev/zero | tr '\\0' x; printf 'TAIL'",
        { max_output_bytes: 4096 },
      );
      expect(truncated.exit_code).toBe(0);
      expect(truncated.truncated).toBe(true);
      expect(truncated.bytes).toBe(10_000);
      expect(truncated.output.length).toBe(4096);
      expect(truncated.output.startsWith('HEAD')).toBe(true);
      expect(truncated.output.endsWith('TAIL')).toBe(true);

      await close(started.session_id);
      expect((await list()).count).toBe(0);
    },
    TEST_TIMEOUT_MS,
  );

  it(
    'enforces the per-host session cap and frees slots on close',
    async () => {
      const first = await startSession();
      const second = await startSession();

      const third = await sessionStart({ host: ALIAS }, ctx);
      expect(third.isError).toBe(true);
      const err = errorOf(third);
      expect(err.code).toBe('too_many_sessions');
      expect(err.kind).toBe('Policy');

      await close(first.session_id);

      const replacement = await startSession();
      expect(replacement.session_id).not.toBe(first.session_id);

      await close(second.session_id);
      await close(replacement.session_id);
      expect((await list()).count).toBe(0);
    },
    TEST_TIMEOUT_MS,
  );

  it(
    'leaves no session shells on the remote host and no local registry entries',
    async () => {
      expect((await list()).count).toBe(0);
      expect(getSessionRegistry().size).toBe(0);

      // 用整行精确匹配（-x）避免 ps/grep 自身命令行被计入；grep 无匹配时
      // 用 `; true` 把管道退出码归零。不要用 awk（内置 hard 规则会拒绝）。
      const check = await sshExec(
        {
          host: ALIAS,
          command:
            "ps -u \"$(id -un)\" -o args= | grep -xF -- 'bash --noprofile --norc'; true",
          timeout_ms: 15_000,
        },
        ctx,
      );
      if (check.isError === true) {
        throw new Error(`residue check failed: ${textOf(check)}`);
      }
      const exec = structured<ExecStructured>(check);
      expect(exec.exit_code).toBe(0);
      expect(exec.stdout.trim()).toBe('');
    },
    TEST_TIMEOUT_MS,
  );
});
