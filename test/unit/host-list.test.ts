import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { loadConfig, loadConfigLazy } from '../../src/config/load.js';
import { resolvePaths } from '../../src/config/paths.js';
import type { ToolContext } from '../../src/tools/common.js';
import { hostList, mergeHostView } from '../../src/tools/host-list.js';
import type { KnownHostEntry, Logger, MCPPaths, RemoteConfig, TrustRegistry } from '../../src/types.js';

const CONFIG = `version: 1
hosts:
  web1:
    host: 10.0.0.5
    user: deploy
    description: 主站
  db1:
    host: 10.0.0.6
    user: ops
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

describe('mergeHostView', () => {
  let config: RemoteConfig;

  beforeEach(async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-merge-'));
    const paths = resolvePaths({ explicit: path.join(root, 'config.yaml'), env: {}, homeDir: root });
    await fs.writeFile(paths.configFile, CONFIG, 'utf8');
    config = await loadConfig(paths);
    await fs.rm(root, { recursive: true, force: true });
  });

  const emptyRegistry: TrustRegistry = { version: 1, hosts: {} };

  it('sorts by alias and marks everything untrusted without a pin', () => {
    const views = mergeHostView({
      config,
      registry: emptyRegistry,
      knownHosts: [],
      security: config.security,
    });
    expect(views.map((v) => v.alias)).toEqual(['db1', 'web1']);
    expect(views.every((v) => v.trusted === false)).toBe(true);
    expect(views.every((v) => v.knownHostsPresent === false)).toBe(true);
  });

  it('exposes description when configured', () => {
    const web = mergeHostView({ config, registry: emptyRegistry, knownHosts: [], security: config.security })
      .find((v) => v.alias === 'web1');
    expect(web?.description).toBe('主站');
  });

  it('is untrusted when the pin does not match any observed key', () => {
    const registry: TrustRegistry = {
      version: 1,
      hosts: {
        web1: {
          fingerprint: 'SHA256:AAAA',
        } as TrustRegistry['hosts'][string],
      },
    };
    const knownHosts: KnownHostEntry[] = [
      { hosts: ['10.0.0.5'], algorithm: 'ssh-ed25519', keyBlob: 'AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholder' } as KnownHostEntry,
    ];
    const web = mergeHostView({ config, registry, knownHosts, security: config.security })
      .find((v) => v.alias === 'web1');
    expect(web?.trusted).toBe(false);
    expect(web?.pinnedFingerprint).toBe('SHA256:AAAA');
  });

  it('is never trusted when hostKeyPolicy is not pinned', () => {
    const security = { ...config.security, hostKeyPolicy: 'off' } as typeof config.security;
    const views = mergeHostView({ config, registry: emptyRegistry, knownHosts: [], security });
    expect(views.every((v) => v.trusted === false)).toBe(true);
  });
});

describe('hostList', () => {
  let root: string;
  let paths: MCPPaths;
  let ctx: ToolContext;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-hostlist-'));
    paths = resolvePaths({ explicit: path.join(root, 'config.yaml'), env: {}, homeDir: root });
    const log = makeLogger();
    ctx = { paths, log, getConfig: loadConfigLazy(paths, log) };
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await fs.rm(root, { recursive: true, force: true });
  });

  it('lists configured hosts as untrusted when no registry or known_hosts exists', async () => {
    await fs.writeFile(paths.configFile, CONFIG, 'utf8');
    const result = await hostList({}, ctx);
    expect(result.isError).toBeFalsy();
    const text = textOf(result);
    expect(text).toContain('untrusted  db1');
    expect(text).toContain('untrusted  web1');
    expect(text).toContain('[no pin]');
  });

  it('reports degraded mode when the trust registry is corrupted', async () => {
    await fs.writeFile(paths.configFile, CONFIG, 'utf8');
    await fs.writeFile(paths.trustRegistryFile, '{not json', 'utf8');
    const result = await hostList({}, ctx);
    expect(result.isError).toBeFalsy();
    const text = textOf(result);
    expect(text).toContain('warning: trust registry could not be read');
    expect(text).toContain('untrusted  web1');
  });

  it('returns a Policy error result when the config file is missing', async () => {
    const result = await hostList({}, ctx);
    expect(result.isError).toBe(true);
  });
});
