import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio, StdioServerTransport, type StdioServerHandle } from '@modelcontextprotocol/server/stdio';
import { loadConfigLazy } from './config/load.js';
import { resolvePaths } from './config/paths.js';
import { EXIT } from './constants.js';
import { ConfigError } from './errors/classes.js';
import { serializeError } from './log.js';
import { installSignalHandlers, shutdown } from './lifecycle.js';
import { registerTool, type ToolContext } from './tools/common.js';
import { hostCheck, hostCheckInput } from './tools/host-check.js';
import { hostList, hostListInput } from './tools/host-list.js';
import type { Logger, MCPPaths } from './types.js';
import { VERSION } from './version.js';

export type { ToolContext } from './tools/common.js';

const INSTRUCTIONS =
  '先用 host_list 查看已配置的主机及其信任状态，再用 host_check 检查目标主机；不要假设主机已受信任。';

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
    await shutdown({ reason: 'transport_closed', log });
    return EXIT.ok;
  } catch (err) {
    log.error({ err: serializeError(err) }, 'server failed');
    return EXIT.internal;
  } finally {
    uninstall?.();
  }
}
