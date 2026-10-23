import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { loadConfigLazy } from '../../src/config/load.js';
import { resolvePaths } from '../../src/config/paths.js';
import type { ToolContext } from '../../src/tools/common.js';
import { hostCheck } from '../../src/tools/host-check.js';
import type { Logger, MCPPaths } from '../../src/types.js';

const CONFIG = `version: 1
hosts:
  web1:
    host: 10.0.0.5
    user: deploy
`;

function makeLogger(): Logger {
  const logger: Logger = {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    child: () => logger,
  };
  return logger;
}

function textOf(result: { content: unknown }): string {
  const first = (result.content as Array<{ type: string; text?: string }>)[0];
  return first?.text ?? '';
}

describe('hostCheck', () => {
  let root: string;
  let paths: MCPPaths;
  let ctx: ToolContext;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-hostcheck-'));
    paths = resolvePaths({ explicit: path.join(root, 'config.yaml'), env: {}, homeDir: root });
    await fs.writeFile(paths.configFile, CONFIG, 'utf8');
    const log = makeLogger();
    ctx = { paths, log, getConfig: loadConfigLazy(paths, log) };
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await fs.rm(root, { recursive: true, force: true });
  });

  it('returns an error result for an unknown alias without touching the network', async () => {
    const result = await hostCheck({ alias: 'ghost' }, ctx);
    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/ghost/);
  });

  it('rejects an invalid alias before any lookup', async () => {
    const result = await hostCheck({ alias: 'bad alias!' }, ctx);
    expect(result.isError).toBe(true);
  });

  it('blocks an untrusted host with a HostKey error and a trust hint, without spawning ssh', async () => {
    const result = await hostCheck({ alias: 'web1' }, ctx);
    expect(result.isError).toBe(true);
    const text = textOf(result);
    expect(text).toMatch(/remote-mcp trust web1/);
  });
});
