import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadConfig } from '../../../src/config/load.js';
import { resolvePaths } from '../../../src/config/paths.js';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const EXAMPLE_CONFIG = path.join(REPO_ROOT, 'config.example.yaml');

describe('config.example.yaml', () => {
  it('loads with the production loader and exposes the documented defaults', async () => {
    const paths = resolvePaths({ explicit: EXAMPLE_CONFIG, env: {} });
    const config = await loadConfig(paths);

    expect(config.version).toBe(1);
    expect(config.sourcePath).toBe(paths.configFile);

    expect(config.defaults.port).toBe(22);
    expect(config.defaults.defaultCwd).toBe('~');
    expect(config.defaults.defaultHost).toBe('web1');
    expect(config.defaults.timeouts).toEqual({ connectMs: 5000, commandMs: 15000, checkMs: 8000 });
    expect(config.defaults.maxOutputBytes).toBe(1024 * 1024);

    expect(config.security.hostKeyPolicy).toBe('pinned');
    expect(config.security.commandPolicy.mode).toBe('enforce');
    expect(config.security.commandPolicy.useDefaultDeny).toBe(true);
    expect(config.security.commandPolicy.allow.length).toBeGreaterThan(0);
    expect(config.security.commandPolicy.confirm.length).toBeGreaterThan(0);
    expect(config.security.commandPolicy.deny.length).toBeGreaterThan(0);
    expect(config.security.audit).toEqual({
      maxBytes: 16 * 1024 * 1024,
      retainDays: 90,
      dateRotate: true,
    });

    expect(config.defaults.sudo.mode).toBe('passwordless');
    expect(config.defaults.sudo.credential).toBeUndefined();
    expect(config.defaults.sudo.allow.length).toBeGreaterThan(0);
    expect(config.defaults.sudo.deny.length).toBeGreaterThan(0);

    expect(config.files.localRoots).toHaveLength(1);
    expect(config.files.localRoots[0]?.endsWith('remote-mcp-files')).toBe(true);
    expect(config.files.remoteDeny).toEqual(['~/.ssh', '/etc']);
    expect(config.files.maxFileBytes).toBe(512 * 1024 * 1024);
    expect(config.files.maxFiles).toBe(10_000);
    expect(config.files.maxTotalBytes).toBe(4 * 1024 * 1024 * 1024);
    expect(config.files.maxDepth).toBe(64);
    expect(config.files.transferTimeoutMs).toBe(300_000);

    expect(config.hosts.web1).toMatchObject({
      host: '203.0.113.10',
      user: 'deploy',
    });
    expect(config.hosts.web1?.identityFile?.endsWith('id_ed25519')).toBe(true);
    expect(config.hosts.web1?.description).toContain('示例，必须替换');
  });
});
