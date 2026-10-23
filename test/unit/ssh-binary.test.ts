import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { resolveSshBinary, resolveToolBinary } from '../../src/ssh/binary.js';

describe('resolveToolBinary', () => {
  it('resolves ssh and ssh-keygen to absolute paths on this machine', async () => {
    for (const name of ['ssh', 'ssh-keygen'] as const) {
      const p = await resolveToolBinary(name);
      expect(path.isAbsolute(p)).toBe(true);
    }
  });

  it.skipIf(process.platform !== 'win32')('resolves taskkill to an absolute path on Windows', async () => {
    expect(path.isAbsolute(await resolveToolBinary('taskkill'))).toBe(true);
  });

  it('returns the same path on repeated calls (cached)', async () => {
    const a = await resolveToolBinary('ssh');
    const b = await resolveToolBinary('ssh');
    expect(b).toBe(a);
  });

  it('rejects unknown binaries via ssh-add-like name missing from PATH', async () => {
    // ssh-add is expected present on Windows OpenSSH; the missing-name path is covered
    // by resolving a tool name that is not in the allowed set at runtime.
    const bogus = 'definitely-not-a-tool' as unknown as 'ssh';
    await expect(resolveToolBinary(bogus)).rejects.toMatchObject({
      code: 'binary_missing',
      kind: 'Internal',
    });
  });
});

describe('resolveSshBinary', () => {
  it('returns a path and a source of path or system', async () => {
    const r = await resolveSshBinary();
    expect(path.isAbsolute(r.path)).toBe(true);
    expect(['path', 'system']).toContain(r.source);
  });
});
