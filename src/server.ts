import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio, StdioServerTransport, type StdioServerHandle } from '@modelcontextprotocol/server/stdio';
import { loadConfigLazy } from './config/load.js';
import { resolvePaths } from './config/paths.js';
import { EXIT } from './constants.js';
import { ConfigError } from './errors/classes.js';
import { serializeError } from './log.js';
import { installSignalHandlers, shutdown } from './lifecycle.js';
import { SHUTDOWN_BUDGET_MS } from './session/constants.js';
import { getSessionRegistry } from './session/registry.js';
import { registerTool, type ToolContext } from './tools/common.js';
import { hostCheck, hostCheckInput } from './tools/host-check.js';
import { hostList, hostListInput } from './tools/host-list.js';
import { sessionClose, sessionCloseInput } from './tools/session-close.js';
import {
  SESSION_CLOSE_ANNOTATIONS,
  SESSION_LIST_ANNOTATIONS,
  SESSION_SEND_ANNOTATIONS,
  SESSION_START_ANNOTATIONS,
} from './tools/session-common.js';
import { sessionList, sessionListInput } from './tools/session-list.js';
import { sessionSend, sessionSendInput } from './tools/session-send.js';
import { sessionStart, sessionStartInput } from './tools/session-start.js';
import { sshDownload, sshDownloadInput } from './tools/ssh-download.js';
import { sshExec, sshExecInput } from './tools/ssh-exec.js';
import { sshReadFile, sshReadFileInput } from './tools/ssh-read-file.js';
import { SSH_SUDO_ANNOTATIONS, sshSudo, sshSudoInput } from './tools/ssh-sudo.js';
import { sshUpload, sshUploadInput } from './tools/ssh-upload.js';
import { sshWriteFile, sshWriteFileInput } from './tools/ssh-write-file.js';
import { READ_FILE_ANNOTATIONS, TRANSFER_ANNOTATIONS } from './tools/transfer-common.js';
import type { Logger, MCPPaths } from './types.js';
import { VERSION } from './version.js';

export type { ToolContext } from './tools/common.js';

const INSTRUCTIONS =
  '先用 host_list 查看已配置的主机及其信任状态，再用 host_check 检查目标主机。' +
  'ssh_exec 仅对已信任的主机执行命令，调用前确认命令的影响面（会修改远端状态、不可幂等）。' +
  '文件传输工具：ssh_upload / ssh_download（recursive=true 走目录 tar + manifest 校验）、' +
  'ssh_read_file（只读，返回 UTF-8 或 base64 内容）、ssh_write_file（原子写入）。' +
  '本地路径受 files.local_roots 限制，远端路径受读/写 deny 限制；覆盖默认关闭，需要时显式传 overwrite=true。' +
  '持久会话工具：session_start 建立常驻 shell（仍需信任主机），session_send 在该 shell 中依次执行命令，' +
  'session_close 优雅关闭，session_list 查看当前会话。会话按 FIFO 串行执行，空闲超时后自动关闭；' +
  '会话内环境变量与 cwd 只属于该 shell，不会影响其他工具调用。' +
  '会话关闭不会杀掉未 kill 的后台任务；需要时先在会话内 kill，或用 ssh_exec 的 timeout 约束一次性命令。' +
  'ssh_sudo 在已信任主机上通过 sudo 执行命令；sudo.mode=password 时必须先运行 ' +
  '`remote-mcp credential set <ref>` 把密码存入系统凭据库（密码只经 stdin 传给 sudo，不进入 argv/env/审计）。' +
  '命令策略由 security.command_policy 控制（mode=off 保持旧行为）；审计写入配置目录的 audit.jsonl，' +
  '默认 16MiB 轮转、保留 90 天，条目会先脱敏再落盘。';

/** 创建一个未注册工具的 McpServer 实例。 */
export function createMcpServer(_ctx: ToolContext): McpServer {
  return new McpServer(
    { name: 'remote-mcp', version: VERSION },
    { instructions: INSTRUCTIONS, capabilities: { tools: {} } },
  );
}

/** 注册 host_list 与 host_check 两个只读工具。 */
export function registerTools(server: McpServer, ctx: ToolContext): void {
  registerTool(
    server,
    {
      name: 'host_list',
      title: '列出远程主机',
      description:
        '列出配置中的远程主机及其信任状态（trusted/untrusted）。不建立任何网络连接。',
      inputSchema: hostListInput,
      handler: (input, c) => hostList(input, c),
    },
    ctx,
  );
  registerTool(
    server,
    {
      name: 'host_check',
      title: '检查远程主机',
      description:
        '对已信任的远程主机执行只读检查（uname、sshd 版本）。若主机未受信任，将返回 HostKey 错误并给出 `remote-mcp trust <alias>` 指引。',
      inputSchema: hostCheckInput,
      handler: (input, c) => hostCheck(input, c),
    },
    ctx,
  );
  registerTool(
    server,
    {
      name: 'ssh_exec',
      title: '执行远程命令',
      description:
        '在已信任的远程主机上通过 bash -lc 执行一条命令，返回 stdout、stderr 与远端退出码。' +
        '退出码 0–254 是远端命令本身的结果；255 表示 ssh 传输层失败（连接、认证或主机密钥问题）。' +
        '不支持 sudo 交互、持久会话或文件传输。命令会修改远端状态，执行前请确认影响面。',
      inputSchema: sshExecInput,
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
      handler: (input, c) => sshExec(input, c),
    },
    ctx,
  );
  registerTool(
    server,
    {
      name: 'ssh_upload',
      title: '上传文件到远程主机',
      description:
        '把本地文件（recursive=true 时为目录）上传到已信任主机的远端路径。' +
        '本地路径必须位于 files.local_roots 内，远端写 deny 路径会被拒绝。' +
        '单文件使用 sftp + sha256 校验；目录使用 tar over ssh + manifest 校验，并通过同目录临时路径原子替换。' +
        'overwrite 默认 false；目标已存在时返回 target_exists。',
      inputSchema: sshUploadInput,
      annotations: TRANSFER_ANNOTATIONS,
      handler: (input, c) => sshUpload(input, c),
    },
    ctx,
  );
  registerTool(
    server,
    {
      name: 'ssh_download',
      title: '从远程主机下载文件',
      description:
        '从已信任主机下载文件（recursive=true 时为目录）到本地路径。' +
        '本地目标必须位于 files.local_roots 内；远端读 deny 路径会被拒绝。' +
        '单文件使用 sftp + sha256 校验；目录使用 tar over ssh + manifest 校验，并通过本地临时目录原子替换。' +
        'overwrite 默认 false；目标已存在时返回 target_exists。',
      inputSchema: sshDownloadInput,
      annotations: TRANSFER_ANNOTATIONS,
      handler: (input, c) => sshDownload(input, c),
    },
    ctx,
  );
  registerTool(
    server,
    {
      name: 'ssh_read_file',
      title: '读取远程文件',
      description:
        '只读地读取已信任主机上的文件内容。返回整文件 sha256/size，以及 UTF-8 文本或 base64 内容；' +
        '可用 tail_lines 只取末尾若干行，max_bytes 限制返回字节数（超出时 truncated=true）。' +
        '~/.ssh 等敏感路径由读 deny 强制拒绝。',
      inputSchema: sshReadFileInput,
      annotations: READ_FILE_ANNOTATIONS,
      handler: (input, c) => sshReadFile(input, c),
    },
    ctx,
  );
  registerTool(
    server,
    {
      name: 'ssh_write_file',
      title: '写入远程文件',
      description:
        '把内容写入已信任主机上的文件（content 为 UTF-8 文本或 base64）。' +
        '在远端同目录创建临时文件，校验 sha256/size 后 chmod 并原子替换；' +
        'mode 省略时保留旧文件权限，新文件使用 0644。overwrite 默认 false。',
      inputSchema: sshWriteFileInput,
      annotations: TRANSFER_ANNOTATIONS,
      handler: (input, c) => sshWriteFile(input, c),
    },
    ctx,
  );

  registerTool(
    server,
    {
      name: 'ssh_sudo',
      title: '以 sudo 执行远程命令',
      description:
        '在已信任的远程主机上通过 sudo 执行一条命令。命令与 sudo 规则分别由 security.command_policy 与 ' +
        'defaults.sudo 约束；read_only/off/deny 会在 spawn 前拒绝。' +
        'sudo.mode=passwordless 使用 `sudo -n`；sudo.mode=password 从系统凭据库读取密码并通过 stdin 传给 sudo，' +
        '因此该模式不支持用户 stdin。密码错误或需要 TTY 返回 SudoPrompt。',
      inputSchema: sshSudoInput,
      annotations: SSH_SUDO_ANNOTATIONS,
      handler: (input, c) => sshSudo(input, c),
    },
    ctx,
  );

  registerSessionTools(server, ctx);
}

/** 注册 P4 持久会话工具（start/send/close/list）。 */
export function registerSessionTools(server: McpServer, ctx: ToolContext): void {
  registerTool(
    server,
    {
      name: 'session_start',
      title: '启动持久会话',
      description:
        '在已信任的远程主机上建立常驻 bash 会话（不分配 TTY），返回 session_id。' +
        '指令、环境变量（env）与 cwd 只作用于该会话；空闲超过 idle_timeout_ms（默认 15 分钟）会自动关闭。' +
        '会话数量受全局/单目标上限约束，超过时返回 too_many_sessions。',
      inputSchema: sessionStartInput,
      annotations: SESSION_START_ANNOTATIONS,
      handler: (input, c) => sessionStart(input, c),
    },
    ctx,
  );
  registerTool(
    server,
    {
      name: 'session_send',
      title: '在会话中执行命令',
      description:
        '在指定持久会话中执行一条命令，返回远端退出码与输出。同一会话内的命令按 FIFO 串行执行，' +
        '执行期间占用主机并发许可；超出会话队列上限时返回 session_busy。' +
        '命令超时（timeout_ms）会关闭该会话并返回 session_timeout。',
      inputSchema: sessionSendInput,
      annotations: SESSION_SEND_ANNOTATIONS,
      handler: (input, c) => sessionSend(input, c),
    },
    ctx,
  );
  registerTool(
    server,
    {
      name: 'session_close',
      title: '关闭会话',
      description:
        '优雅关闭持久会话（发送 Q 并关闭 stdin，宽限期后强杀进程树），返回退出码/信号等事实。' +
        '关闭是幂等的；未知或已移除的会话返回 unknown_session。' +
        '注意：关闭会话不会杀掉未 kill 的后台任务；需要时先在会话内 kill，或用 ssh_exec 的 timeout 约束一次性命令。',
      inputSchema: sessionCloseInput,
      annotations: SESSION_CLOSE_ANNOTATIONS,
      handler: (input, c) => sessionClose(input, c),
    },
    ctx,
  );
  registerTool(
    server,
    {
      name: 'session_list',
      title: '列出持久会话',
      description:
        '列出本进程内的会话状态快照（状态、队列深度、已执行命令数、累计输出字节等）。' +
        '不建立连接、不占用并发许可，也不返回命令或输出内容。',
      inputSchema: sessionListInput,
      annotations: SESSION_LIST_ANNOTATIONS,
      handler: (input, c) => sessionList(input, c),
    },
    ctx,
  );
}

/** 关闭所有持久会话（最多 SHUTDOWN_BUDGET_MS）；closeAll 永不 reject。 */
async function closeAllSessions(reason: string): Promise<void> {
  try {
    await getSessionRegistry().closeAll(reason, SHUTDOWN_BUDGET_MS);
  } catch {
    // closeAll 约定永不 reject；这里再兜底一次。
  }
}

export interface ServeOptions {
  log: Logger;
  configPath?: string;
  env: NodeJS.ProcessEnv;
}

/**
 * 包装 transport 的 onclose：serveStdio 会覆盖 onclose，这里通过访问器在它赋值时接管，
 * 并返回一个在 transport 关闭时 resolve 的 Promise。
 */
function watchClose(transport: StdioServerTransport): Promise<void> {
  let resolveClosed: () => void = () => undefined;
  const closed = new Promise<void>((resolve) => {
    resolveClosed = resolve;
  });
  let inner: (() => void) | undefined;
  Object.defineProperty(transport, 'onclose', {
    configurable: true,
    enumerable: true,
    get: () => (): void => {
      inner?.();
      resolveClosed();
    },
    set: (fn: (() => void) | undefined) => {
      inner = fn;
    },
  });
  return closed;
}

/**
 * 以 MCP stdio 运行服务器。配置损坏不阻止连接建立（错误在工具调用时返回）。
 * 传输关闭或收到关闭信号后执行 shutdown，返回 EXIT.ok；未预期异常返回 EXIT.internal。
 */
export async function serve(opts: ServeOptions): Promise<number> {
  const { log, configPath, env } = opts;

  let paths: MCPPaths;
  try {
    paths = resolvePaths({ explicit: configPath, env });
  } catch (err) {
    log.error({ err: serializeError(err) }, 'cannot resolve config path');
    return err instanceof ConfigError ? EXIT.config : EXIT.internal;
  }

  let uninstall: (() => void) | undefined;
  try {
    const ctx: ToolContext = {
      paths,
      log,
      getConfig: loadConfigLazy(paths, log),
    };

    const wire = new StdioServerTransport();
    const wireClosed = watchClose(wire);

    let handle: StdioServerHandle | undefined;
    let finish: () => void = () => undefined;
    const finished = new Promise<void>((resolve) => {
      finish = resolve;
    });

    uninstall = installSignalHandlers({
      stdin: process.stdin,
      onShutdown: (reason) => {
        void (async () => {
          await closeAllSessions(reason);
          await shutdown({ reason, log });
          await handle?.close().catch(() => undefined);
          finish();
        })();
      },
    });

    const factory = (): McpServer => {
      const server = createMcpServer(ctx);
      registerTools(server, ctx);
      return server;
    };

    handle = serveStdio(factory, {
      transport: wire,
      onerror: (err) => log.error({ err: serializeError(err) }, 'transport error'),
    });
    log.info({ configFile: paths.configFile, configSource: paths.source, version: VERSION }, 'serving MCP over stdio');

    await Promise.race([wireClosed, finished]);
    uninstall();
    uninstall = undefined;
    await closeAllSessions('transport_closed');
    await shutdown({ reason: 'transport_closed', log });
    return EXIT.ok;
  } catch (err) {
    log.error({ err: serializeError(err) }, 'server failed');
    return EXIT.internal;
  } finally {
    uninstall?.();
  }
}
