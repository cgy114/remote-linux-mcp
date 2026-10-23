import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { loadConfig, loadConfigLazy } from '../../../src/config/load.js';
import { resolvePaths } from '../../../src/config/paths.js';
import { ConfigError } from '../../../src/errors/classes.js';
import type { Logger, MCPPaths } from '../../../src/types.js';

const VALID = `version: 1
hosts:
  web1:
    host: 10.0.0.5
    user: deploy
`;

function makeLogger(): Logger & { warn: ReturnType<typeof vi.fn> } {
  const logger: Logger = {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    child: () => logger,
  };
  return logger as Logger & { warn: ReturnType<typeof vi.fn> };
}

async function expectConfigError(p: Promise<unknown>, code: string): Promise<ConfigError> {
  let caught: unknown;
  try {
    await p;
  } catch (err) {
    caught = err;
  }
  expect(caught).toBeInstanceOf(ConfigError);
  expect((caught as ConfigError).code).toBe(code);
  return caught as ConfigError;
}

describe('loadConfig', () => {
  let root: string;
  let paths: MCPPaths;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-load-'));
    paths = resolvePaths({ explicit: path.join(root, 'config.yaml'), env: {}, homeDir: root });
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await fs.rm(root, { recursive: true, force: true });
  });

  async function write(text: string): Promise<void> {
    await fs.writeFile(paths.configFile, text, 'utf8');
  }

  it('loads a minimal config and expands defaults', async () => {
    await write(VALID);
    const cfg = await loadConfig(paths);
    expect(cfg.version).toBe(1);
    expect(cfg.sourcePath).toBe(paths.configFile);
    expect(cfg.baseDir).toBe(paths.configDir);
    expect(cfg.defaults.port).toBe(22);
    expect(cfg.security).toEqual({ hostKeyPolicy: 'pinned' });
    expect(cfg.hosts.web1).toEqual({ host: '10.0.0.5', user: 'deploy' });
  });

  it('maps snake_case host fields to camelCase', async () => {
    await write(`version: 1
hosts:
  db:
    host: db.internal
    user: ops
    port: 2222
    proxy_jump: bastion
    default_cwd: /srv/app
    description: primary db
`);
    const cfg = await loadConfig(paths);
    expect(cfg.hosts.db).toEqual({
      host: 'db.internal',
      user: 'ops',
      port: 2222,
      proxyJump: 'bastion',
      defaultCwd: '/srv/app',
      description: 'primary db',
    });
  });

  it('maps defaults and security into camelCase', async () => {
    await write(`version: 1
defaults:
  port: 2200
  default_cwd: /home/x
  timeouts:
    command_ms: 30000
  max_output_bytes: 65536
  sudo:
    mode: passwordless
    allow: ["systemctl status *"]
security:
  host_key_policy: pinned
hosts:
  a: { host: h, user: u }
`);
    const cfg = await loadConfig(paths);
    expect(cfg.defaults).toEqual({
      port: 2200,
      defaultCwd: '/home/x',
      timeouts: { connectMs: 5000, commandMs: 30000, checkMs: 8000 },
      maxOutputBytes: 65536,
      sudo: { mode: 'passwordless', allow: ['systemctl status *'], deny: [] },
    });
  });

  it('rejects a missing version', async () => {
    await write('hosts:\n  a: { host: h, user: u }\n');
    const err = await expectConfigError(loadConfig(paths), 'schema');
    expect(err.issues?.length).toBeGreaterThan(0);
    expect(JSON.stringify(err.issues)).toContain('version');
  });

  it('rejects a missing hosts section', async () => {
    await write('version: 1\n');
    await expectConfigError(loadConfig(paths), 'schema');
  });

  it('rejects empty hosts', async () => {
    await write('version: 1\nhosts: {}\n');
    await expectConfigError(loadConfig(paths), 'schema');
  });

  it('rejects unknown top-level and host-level fields', async () => {
    await write('version: 1\nfoo: 1\nhosts:\n  a: { host: h, user: u }\n');
    await expectConfigError(loadConfig(paths), 'schema');
    await write('version: 1\nhosts:\n  a: { host: h, user: u, extra: 1 }\n');
    await expectConfigError(loadConfig(paths), 'schema');
  });

  it('rejects port given as a string "22", 0, 70000, and decimals', async () => {
    for (const port of ['"22"', '0', '70000', '22.5']) {
      await write(`version: 1\nhosts:\n  a: { host: h, user: u, port: ${port} }\n`);
      await expectConfigError(loadConfig(paths), 'schema');
    }
  });

  it('rejects a non-canonical alias key (leading -, uppercase, reserved)', async () => {
    for (const key of ['-x', 'Web', 'default', 'serve', 'trust']) {
      await write(`version: 1\nhosts:\n  "${key}": { host: h, user: u }\n`);
      await expectConfigError(loadConfig(paths), 'schema');
    }
  });

  it('resolves a relative identity_file against the config directory', async () => {
    await write(`version: 1
hosts:
  a: { host: h, user: u, identity_file: keys/id_ed25519 }
`);
    const cfg = await loadConfig(paths);
    expect(cfg.hosts.a?.identityFile).toBe(path.join(paths.configDir, 'keys', 'id_ed25519'));
    expect(path.isAbsolute(cfg.hosts.a?.identityFile ?? '')).toBe(true);
  });

  it('expands ~ in identity_file to the home directory', async () => {
    await write(`version: 1
hosts:
  a: { host: h, user: u, identity_file: "~/.ssh/id_rsa" }
`);
    const cfg = await loadConfig(paths);
    expect(cfg.hosts.a?.identityFile).toBe(path.join(os.homedir(), '.ssh', 'id_rsa'));
  });

  it('keeps an absolute identity_file as-is', async () => {
    const abs = path.join(root, 'abs-key');
    await write(`version: 1\nhosts:\n  a: { host: h, user: u, identity_file: "${abs.replace(/\\/g, '/')}" }\n`);
    const cfg = await loadConfig(paths);
    expect(cfg.hosts.a?.identityFile).toBe(path.normalize(abs));
  });

  it('rejects ~other in identity_file with ConfigError(schema)', async () => {
    await write(`version: 1\nhosts:\n  a: { host: h, user: u, identity_file: "~other/key" }\n`);
    await expectConfigError(loadConfig(paths), 'schema');
  });

  it('resolves a relative known_hosts_file against the config directory', async () => {
    await write(`version: 1
security:
  known_hosts_file: pins/known_hosts
hosts:
  a: { host: h, user: u }
`);
    const cfg = await loadConfig(paths);
    expect(cfg.security.knownHostsFile).toBe(path.join(paths.configDir, 'pins', 'known_hosts'));
  });

  it('leaves knownHostsFile undefined when not configured', async () => {
    await write(VALID);
    const cfg = await loadConfig(paths);
    expect(cfg.security.knownHostsFile).toBeUndefined();
  });

  it('reports duplicate YAML keys as duplicate_key', async () => {
    await write(`version: 1
hosts:
  a: { host: h, user: u }
  a: { host: h2, user: u2 }
`);
    await expectConfigError(loadConfig(paths), 'duplicate_key');
  });

  it('reports YAML syntax errors as parse', async () => {
    await write('version: 1\nhosts: [unclosed\n');
    await expectConfigError(loadConfig(paths), 'parse');
  });

  it('reports a missing file as not_found', async () => {
    await expectConfigError(loadConfig(paths), 'not_found');
  });

  it('reports a read failure (path is a directory) as io', async () => {
    await fs.mkdir(paths.configFile);
    await expectConfigError(loadConfig(paths), 'io');
  });

  it('re-reads the disk on every call (no caching in loadConfig itself)', async () => {
    await write(VALID);
    const first = await loadConfig(paths);
    await write(VALID.replace('deploy', 'ops'));
    const second = await loadConfig(paths);
    expect(first.hosts.web1?.user).toBe('deploy');
    expect(second.hosts.web1?.user).toBe('ops');
  });
});

describe('loadConfigLazy', () => {
  let root: string;
  let paths: MCPPaths;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-lazy-'));
    paths = resolvePaths({ explicit: path.join(root, 'config.yaml'), env: {}, homeDir: root });
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await fs.rm(root, { recursive: true, force: true });
  });

  it('reads the file once and caches a successful result', async () => {
    await fs.writeFile(paths.configFile, VALID, 'utf8');
    const readSpy = vi.spyOn(fs, 'readFile');
    const log = makeLogger();
    const get = loadConfigLazy(paths, log);

    const a = await get();
    const b = await get();
    expect(b).toBe(a);
    expect(a.hosts.web1?.host).toBe('10.0.0.5');
    expect(readSpy).toHaveBeenCalledTimes(1);
    expect(log.warn).not.toHaveBeenCalled();
  });

  it('caches the same error instance on failure and does not re-read the disk', async () => {
    const readSpy = vi.spyOn(fs, 'readFile');
    const log = makeLogger();
    const get = loadConfigLazy(paths, log);

    let first: unknown;
    let second: unknown;
    try {
      await get();
    } catch (err) {
      first = err;
    }
    try {
      await get();
    } catch (err) {
      second = err;
    }

    expect(first).toBeInstanceOf(ConfigError);
    expect((first as ConfigError).code).toBe('not_found');
    expect(second).toBe(first);
    expect(readSpy).toHaveBeenCalledTimes(1);
    expect(log.warn).toHaveBeenCalledTimes(1);
  });

  it('does not re-read even after the file appears following a failure', async () => {
    const readSpy = vi.spyOn(fs, 'readFile');
    const get = loadConfigLazy(paths, makeLogger());
    await expect(get()).rejects.toBeInstanceOf(ConfigError);

    await fs.writeFile(paths.configFile, VALID, 'utf8');
    await expect(get()).rejects.toBeInstanceOf(ConfigError);
    expect(readSpy).toHaveBeenCalledTimes(1);
  });

  it('shares one in-flight load across concurrent callers', async () => {
    await fs.writeFile(paths.configFile, VALID, 'utf8');
    const readSpy = vi.spyOn(fs, 'readFile');
    const get = loadConfigLazy(paths, makeLogger());

    const [a, b] = await Promise.all([get(), get()]);
    expect(b).toBe(a);
    expect(readSpy).toHaveBeenCalledTimes(1);
  });
});
