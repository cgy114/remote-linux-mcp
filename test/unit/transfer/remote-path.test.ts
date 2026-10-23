import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  assertRemotePathAllowed,
  assertRemoteRealpath,
  basenameRemote,
  buildRemoteDenyLists,
  BUILTIN_REMOTE_DENY_READ,
  BUILTIN_REMOTE_DENY_WRITE,
  dirnameRemote,
  expandRemotePath,
  isSameOrInside,
  normalizeRemotePath,
  renderRemoteShellPath,
} from '../../../src/policy/remote-path.js';

describe('remote-path', () => {
  describe('buildRemoteDenyLists', () => {
    it('contains every builtin entry in both lists', () => {
      const lists = buildRemoteDenyLists(undefined);
      for (const entry of BUILTIN_REMOTE_DENY_READ) expect(lists.read).toContain(entry);
      for (const entry of BUILTIN_REMOTE_DENY_WRITE) expect(lists.write).toContain(entry);
    });

    it('appends files.remoteDeny to read and write, normalizing and deduping', () => {
      const lists = buildRemoteDenyLists({ remoteDeny: ['/srv/private/', '~/secret', '/etc'] });
      expect(lists.read).toContain('/srv/private');
      expect(lists.read).toContain('~/secret');
      expect(lists.write).toContain('/srv/private');
      expect(lists.write).toContain('~/secret');
      expect(lists.write.filter((entry) => entry === '/etc')).toHaveLength(1);
      // 配置项读写都加；内置读列表本身没有 "/etc"。
      expect(lists.read).toContain('/etc');
      expect(buildRemoteDenyLists({ remoteDeny: [] }).read).not.toContain('/etc');
    });

    it('cannot remove builtins by configuration', () => {
      const lists = buildRemoteDenyLists({ remoteDeny: [] });
      expect(lists.read).toContain('~/.ssh');
      expect(lists.read).toContain('/etc/shadow');
      expect(lists.write).toContain('/usr');
      expect(lists.write).toContain('~/.ssh');
    });
  });

  describe('normalizeRemotePath', () => {
    it('collapses dot segments and duplicate slashes', () => {
      expect(normalizeRemotePath('/a/./b//c/../d', '/').absolute).toBe('/a/b/d');
      expect(normalizeRemotePath('/a/b/../..', '/').absolute).toBe('/');
      expect(() => normalizeRemotePath('/../x', '/')).toThrow(
        expect.objectContaining({ code: 'remote_path_escape' }),
      );
    });

    it('resolves relative paths against cwd', () => {
      expect(normalizeRemotePath('b/../c', '~/work').absolute).toBe('~/work/c');
      expect(normalizeRemotePath('c', '/srv').absolute).toBe('/srv/c');
    });

    it('marks home exactly', () => {
      expect(normalizeRemotePath('~', '/').isHome).toBe(true);
      expect(normalizeRemotePath('~/', '/').absolute).toBe('~');
      expect(normalizeRemotePath('~/x', '/').isHome).toBe(false);
      expect(normalizeRemotePath('.', '~').absolute).toBe('~');
    });

    it('rejects escaping above / or ~', () => {
      expect(() => normalizeRemotePath('/..', '/')).toThrow(
        expect.objectContaining({ code: 'remote_path_escape' }),
      );
      expect(() => normalizeRemotePath('~/..', '/')).toThrow(
        expect.objectContaining({ code: 'remote_path_escape' }),
      );
      expect(() => normalizeRemotePath('../x', '~')).toThrow(
        expect.objectContaining({ code: 'remote_path_escape' }),
      );
      expect(() => normalizeRemotePath('a/../../../b', '/srv')).toThrow(
        expect.objectContaining({ code: 'remote_path_escape' }),
      );
    });

    it('rejects invalid paths', () => {
      const cases = [
        ['', '/'],
        ['~user/x', '/'],
        ['/a\u0000b', '/'],
        ['/a\rb', '/'],
        ['/a\nb', '/'],
        ['/a\uD800b', '/'],
        ['a'.repeat(4097), '/'],
      ] as const;
      for (const [raw, cwd] of cases) {
        expect(() => normalizeRemotePath(raw, cwd)).toThrow(
          expect.objectContaining({ code: 'remote_path_invalid' }),
        );
      }
    });

    it('is idempotent for generated rooted paths', () => {
      const parts = fc.array(fc.constantFrom('a', 'b', 'x y', '.', '..'), { maxLength: 6 });
      fc.assert(
        fc.property(parts, (rawParts) => {
          let depth = 0;
          let escapes = false;
          for (const part of rawParts) {
            if (part === '.') continue;
            if (part === '..') {
              depth -= 1;
              if (depth < 0) escapes = true;
            } else {
              depth += 1;
            }
          }
          fc.pre(!escapes);
          const raw = rawParts.length === 0 ? '~' : `~/${rawParts.join('/')}`;
          const first = normalizeRemotePath(raw, '/').absolute;
          const second = normalizeRemotePath(first, '/').absolute;
          return first === second && !first.includes('//') && !first.includes('/./') && !first.includes('/../');
        }),
        { numRuns: 200 },
      );
    });
  });

  describe('deny matching', () => {
    const lists = buildRemoteDenyLists({ remoteDeny: ['/srv/private'] });

    it('matches on segment boundaries, not string prefixes', () => {
      expect(() => assertRemotePathAllowed('/etc/passwd', 'write', lists.write)).toThrow(
        expect.objectContaining({ code: 'remote_denied_write' }),
      );
      expect(() => assertRemotePathAllowed('/etcetera', 'write', lists.write)).not.toThrow();
      expect(() => assertRemotePathAllowed('/etcetera/passwd', 'write', lists.write)).not.toThrow();
      expect(() => assertRemotePathAllowed('/etc/../etcetera', 'write', lists.write)).not.toThrow();
    });

    it('separates read and write lists', () => {
      expect(() => assertRemotePathAllowed('/etc/shadow', 'read', lists.read)).toThrow(
        expect.objectContaining({ code: 'remote_denied_read' }),
      );
      expect(() => assertRemotePathAllowed('/etc/shadow', 'write', lists.write)).toThrow(
        expect.objectContaining({ code: 'remote_denied_write' }),
      );
      expect(() => assertRemotePathAllowed('/etc/passwd', 'read', lists.read)).not.toThrow();
      expect(() => assertRemotePathAllowed('~/.ssh/id_rsa', 'read', lists.read)).toThrow(
        expect.objectContaining({ code: 'remote_denied_read' }),
      );
      expect(() => assertRemotePathAllowed('~/.ssh/id_rsa', 'write', lists.write)).toThrow(
        expect.objectContaining({ code: 'remote_denied_write' }),
      );
    });

    it('applies configured entries to both accesses', () => {
      expect(() => assertRemotePathAllowed('/srv/private/a', 'read', lists.read)).toThrow(
        expect.objectContaining({ code: 'remote_denied_read' }),
      );
      expect(() => assertRemotePathAllowed('/srv/private/a', 'write', lists.write)).toThrow(
        expect.objectContaining({ code: 'remote_denied_write' }),
      );
      expect(() => assertRemotePathAllowed('/srv/privateer', 'read', lists.read)).not.toThrow();
      expect(() => assertRemotePathAllowed('/srv/private/../public', 'read', lists.read)).not.toThrow();
    });

    it('checks realpath against home-expanded deny entries', () => {
      const home = '/home/u';
      expect(() =>
        assertRemoteRealpath('/home/u/.ssh/id_rsa', '~/link', 'read', lists.read, home),
      ).toThrow(expect.objectContaining({ code: 'remote_denied_read' }));
      expect(() =>
        assertRemoteRealpath('/srv/ok/file', '~/link', 'read', lists.read, home),
      ).not.toThrow();
      expect(() =>
        assertRemoteRealpath('/srv/private/real', '~/link', 'write', lists.write),
      ).toThrow(expect.objectContaining({ code: 'remote_denied_write' }));
    });
  });

  describe('path helpers', () => {
    it('expands home', () => {
      expect(expandRemotePath('~', '/home/u')).toBe('/home/u');
      expect(expandRemotePath('~/a/b', '/home/u/')).toBe('/home/u/a/b');
      expect(expandRemotePath('/etc/x', '/home/u')).toBe('/etc/x');
      expect(expandRemotePath('~/x', '/')).toBe('/x');
      expect(() => expandRemotePath('~/x', 'relative')).toThrow(
        expect.objectContaining({ code: 'remote_path_invalid' }),
      );
    });

    it('renders shell paths with $HOME and single quotes', () => {
      expect(renderRemoteShellPath('~')).toBe('"$HOME"');
      expect(renderRemoteShellPath('~/a b')).toBe(`"$HOME"'/a b'`);
      expect(renderRemoteShellPath("/it's")).toBe(`'/it'\\''s'`);
      expect(renderRemoteShellPath('/plain')).toBe(`'/plain'`);
      expect(() => renderRemoteShellPath('~user/x')).toThrow(
        expect.objectContaining({ code: 'remote_path_invalid' }),
      );
    });

    it('computes dirname and basename', () => {
      expect(dirnameRemote('/a/b/c')).toBe('/a/b');
      expect(dirnameRemote('/a')).toBe('/');
      expect(dirnameRemote('~/a')).toBe('~');
      expect(dirnameRemote('~')).toBe('~');
      expect(basenameRemote('/a/b/c')).toBe('c');
      expect(basenameRemote('~/a')).toBe('a');
      expect(basenameRemote('/')).toBe('/');
      expect(basenameRemote('~')).toBe('~');
    });

    it('isSameOrInside uses segments', () => {
      expect(isSameOrInside('/etc', '/etc')).toBe(true);
      expect(isSameOrInside('/etc', '/etc/passwd')).toBe(true);
      expect(isSameOrInside('/etc/', '/etc/passwd')).toBe(true);
      expect(isSameOrInside('/etc', '/etcetera')).toBe(false);
      expect(isSameOrInside('/etc', '/etcetera/passwd')).toBe(false);
      expect(isSameOrInside('/', '/anything')).toBe(true);
      expect(isSameOrInside('~/.ssh', '~/.ssh/key')).toBe(true);
      expect(isSameOrInside('~/.ssh', '~/.sshx')).toBe(false);
      fc.assert(
        fc.property(fc.constantFrom('a', 'b', 'x y'), (name) => {
          return (
            isSameOrInside('/srv', `/srv/${name}`) &&
            !isSameOrInside('/srv', `/srv-${name}`) &&
            !isSameOrInside('~/cfg', `~/cfg-${name}`)
          );
        }),
        { numRuns: 50 },
      );
    });
  });
});
