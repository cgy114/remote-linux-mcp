import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ConfigError } from '../../../src/errors/classes.js';
import { expandHome, normalizePath, resolvePaths } from '../../../src/config/paths.js';

describe('resolvePaths', () => {
  let root: string;
  let home: string;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'remote-mcp-paths-'));
    home = path.join(root, 'home');
    await fs.mkdir(home, { recursive: true });
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  it('uses the explicit flag first (source=flag) even when env is set', () => {
    const flagFile = path.join(root, 'flag', 'my.yaml');
    const p = resolvePaths({
      explicit: flagFile,
      env: { REMOTE_MCP_CONFIG: path.join(root, 'env.yaml') },
      homeDir: home,
    });
    expect(p.source).toBe('flag');
    expect(p.configFile).toBe(normalizePath(flagFile));
  });

  it('falls back to REMOTE_MCP_CONFIG (source=env)', () => {
    const envFile = path.join(root, 'env', 'config.yaml');
    const p = resolvePaths({ env: { REMOTE_MCP_CONFIG: envFile }, homeDir: home });
    expect(p.source).toBe('env');
    expect(p.configFile).toBe(normalizePath(envFile));
  });

  it('uses <home>/.remote-mcp/config.yaml by default (source=default)', () => {
    const p = resolvePaths({ env: {}, homeDir: home });
    expect(p.source).toBe('default');
    expect(p.configFile).toBe(path.join(home, '.remote-mcp', 'config.yaml'));
  });

  it('derives sibling files from configDir', () => {
    const p = resolvePaths({ explicit: path.join(root, 'cfg', 'config.yaml'), env: {}, homeDir: home });
    const dir = path.join(root, 'cfg');
    expect(p.configDir).toBe(dir);
    expect(p.knownHostsFile).toBe(path.join(dir, 'known_hosts'));
    expect(p.trustRegistryFile).toBe(path.join(dir, 'trusted.json'));
    expect(p.trustLockFile).toBe(path.join(dir, '.trust.lock'));
  });

  it('never derives the default path from cwd', () => {
    const p = resolvePaths({ env: {}, homeDir: home });
    expect(p.configFile.startsWith(process.cwd() + path.sep)).toBe(false);
    expect(path.isAbsolute(p.configFile)).toBe(true);
  });

  it('expands ~ in the explicit path before resolving', () => {
    const p = resolvePaths({ explicit: '~/alt/config.yaml', env: {}, homeDir: home });
    expect(p.configFile).toBe(path.join(home, 'alt', 'config.yaml'));
  });

  it('expands ~ in the env path', () => {
    const p = resolvePaths({ env: { REMOTE_MCP_CONFIG: '~/x.yaml' }, homeDir: home });
    expect(p.configFile).toBe(path.join(home, 'x.yaml'));
  });

  it('returns an absolute configFile for an explicit relative path', () => {
    const p = resolvePaths({ explicit: 'rel/config.yaml', env: {}, homeDir: home });
    expect(path.isAbsolute(p.configFile)).toBe(true);
  });

  it('rejects an explicit path that is an existing directory', async () => {
    const dir = path.join(root, 'adir');
    await fs.mkdir(dir);
    let caught: unknown;
    try {
      resolvePaths({ explicit: dir, env: {}, homeDir: home });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ConfigError);
    expect((caught as ConfigError).code).toBe('schema');
  });

  it('rejects an env path that is an existing directory', async () => {
    const dir = path.join(root, 'envdir');
    await fs.mkdir(dir);
    let caught: unknown;
    try {
      resolvePaths({ env: { REMOTE_MCP_CONFIG: dir }, homeDir: home });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ConfigError);
    expect((caught as ConfigError).code).toBe('schema');
  });

  it('does not reject a non-existent path (missing file is loadConfig\'s concern)', () => {
    expect(() =>
      resolvePaths({ explicit: path.join(root, 'nope.yaml'), env: {}, homeDir: home }),
    ).not.toThrow();
  });

  it('treats an empty env value as unset', () => {
    const p = resolvePaths({ env: { REMOTE_MCP_CONFIG: '' }, homeDir: home });
    expect(p.source).toBe('default');
  });
});

describe('normalizePath', () => {
  it('strips a trailing separator', () => {
    const p = path.join(os.tmpdir(), 'x', 'y') + path.sep;
    expect(normalizePath(p)).toBe(path.join(os.tmpdir(), 'x', 'y'));
  });

  it('keeps the filesystem root intact', () => {
    const root = path.parse(process.cwd()).root;
    expect(normalizePath(root)).toBe(root);
  });

  it('preserves case', () => {
    const p = path.join(os.tmpdir(), 'MixedCase', 'Config.YAML');
    expect(normalizePath(p)).toBe(path.join(os.tmpdir(), 'MixedCase', 'Config.YAML'));
  });

  it('returns an absolute path', () => {
    expect(path.isAbsolute(normalizePath('relative/dir/'))).toBe(true);
  });
});

describe('expandHome', () => {
  const home = path.join(os.tmpdir(), 'fake-home');

  it('expands bare ~', () => {
    expect(expandHome('~', home)).toBe(home);
  });

  it('expands ~/...', () => {
    expect(expandHome('~/a/b.yaml', home)).toBe(path.join(home, 'a', 'b.yaml'));
  });

  it('expands ~\\... (Windows separator)', () => {
    expect(expandHome('~\\a\\b.yaml', home)).toBe(path.join(home, 'a', 'b.yaml'));
  });

  it('throws ConfigError(schema) for ~other', () => {
    let caught: unknown;
    try {
      expandHome('~other/x', home);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ConfigError);
    expect((caught as ConfigError).code).toBe('schema');
  });

  it('returns other paths unchanged', () => {
    expect(expandHome('/abs/path', home)).toBe('/abs/path');
    expect(expandHome('rel/path', home)).toBe('rel/path');
    expect(expandHome('a~b', home)).toBe('a~b');
  });
});
