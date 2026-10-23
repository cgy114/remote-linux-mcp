import { describe, expect, it } from 'vitest';
import {
  diffManifests,
  digestManifest,
  normalizeManifestEntry,
  parseManifest,
  renderManifestLine,
  sortManifestEntries,
  type ManifestEntry,
} from '../../../src/transfer/manifest.js';

const A: ManifestEntry = {
  path: 'a.txt',
  type: 'file',
  size: 3,
  mode: 0o644,
  sha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
};
const B: ManifestEntry = { path: 'sub', type: 'dir', size: 0, mode: 0o755 };
const C: ManifestEntry = { path: 'sub/b.txt', type: 'file', size: 5, mode: 0o600 };
const LINK: ManifestEntry = {
  path: 'link',
  type: 'symlink',
  size: 0,
  mode: 0o777,
  linkTarget: 'a.txt',
};

describe('manifest', () => {
  describe('normalize/sort', () => {
    it('sorts by path code point order', () => {
      const sorted = sortManifestEntries([C, LINK, A, B]);
      expect(sorted.map((entry) => entry.path)).toEqual(['a.txt', 'link', 'sub', 'sub/b.txt']);
    });

    it('masks mode to 0o777 and lowercases sha256', () => {
      const entry = normalizeManifestEntry({ ...A, mode: 0o4755, sha256: A.sha256!.toUpperCase() });
      expect(entry.mode).toBe(0o755);
      expect(entry.sha256).toBe(A.sha256);
    });

    it('rejects absolute paths, dot segments and bad sha256', () => {
      expect(() => normalizeManifestEntry({ ...A, path: '/abs' })).toThrow(
        expect.objectContaining({ code: 'remote_manifest_failed' }),
      );
      expect(() => normalizeManifestEntry({ ...A, path: 'a/../b' })).toThrow(
        expect.objectContaining({ code: 'remote_manifest_failed' }),
      );
      expect(() => normalizeManifestEntry({ ...A, sha256: 'abc' })).toThrow(
        expect.objectContaining({ code: 'remote_manifest_failed' }),
      );
      expect(() => normalizeManifestEntry({ ...A, type: 'fifo' as never })).toThrow(
        expect.objectContaining({ code: 'remote_manifest_failed' }),
      );
    });
  });

  describe('render/parse', () => {
    it('roundtrips entries with tabs, unicode and newline link targets', () => {
      const weird: ManifestEntry = {
        path: 'a\tb/ü.txt',
        type: 'symlink',
        size: 0,
        mode: 0o777,
        linkTarget: 'line1\nline2',
      };
      const text = renderManifestLine(weird);
      expect(text.startsWith('v1\t')).toBe(true);
      expect(text).not.toContain('a\tb');
      expect(parseManifest(text)).toEqual([weird]);
    });

    it('roundtrips many entries deterministically', () => {
      const entries = [C, A, LINK, B];
      const text = entries.map((entry) => renderManifestLine(entry)).join('\n') + '\n';
      expect(parseManifest(text)).toEqual(sortManifestEntries(entries));
    });

    it('rejects malformed manifest text', () => {
      const valid = renderManifestLine(A);
      const cases = [
        '',
        'v2\tx',
        valid.replace(/^v1/, 'v2'),
        `${valid}\t\x00extra`,
        valid.replace('v1', 'v1\t'),
        'v1\tnot-base64\ta\tMQ==\tNjQ0\t\t',
      ];
      // 空文本是合法的空清单
      expect(parseManifest(cases[0]!)).toEqual([]);
      for (const text of cases.slice(1)) {
        expect(() => parseManifest(text)).toThrow(
          expect.objectContaining({ code: 'remote_manifest_failed' }),
        );
      }
    });
  });

  describe('digest', () => {
    it('is deterministic regardless of input order', () => {
      const d1 = digestManifest([A, B, C, LINK]);
      const d2 = digestManifest([LINK, C, B, A]);
      expect(d1).toBe(d2);
      expect(d1).toMatch(/^[0-9a-f]{64}$/);
    });

    it('changes when content metadata changes', () => {
      const base = digestManifest([A]);
      expect(digestManifest([{ ...A, mode: 0o600 }])).not.toBe(base);
      expect(digestManifest([{ ...A, sha256: '0'.repeat(64) }])).not.toBe(base);
    });

    it('distinguishes empty manifest', () => {
      expect(digestManifest([])).toBe(
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      );
    });
  });

  describe('diff', () => {
    it('reports missing, extra, changed and same', () => {
      const expected = [A, B, { ...C, sha256: '0'.repeat(64) }, LINK];
      const actual = [
        { ...A, size: 4 },
        B,
        { ...C, mode: 0o644, sha256: '1'.repeat(64) },
        { path: 'extra.txt', type: 'file' as const, size: 1, mode: 0o644 },
      ];
      const diff = diffManifests(expected, actual);
      expect(diff.missing.map((entry) => entry.path)).toEqual(['link']);
      expect(diff.extra.map((entry) => entry.path)).toEqual(['extra.txt']);
      expect(diff.same).toBe(1);
      expect(diff.changed).toHaveLength(2);
      const aChange = diff.changed.find((change) => change.path === 'a.txt');
      expect(aChange?.reasons).toContain('size');
      const cChange = diff.changed.find((change) => change.path === 'sub/b.txt');
      expect(cChange?.reasons).toEqual(expect.arrayContaining(['mode', 'sha256']));
    });

    it('ignores directory size differences', () => {
      const expected: ManifestEntry[] = [{ ...B, size: 0 }];
      const actual: ManifestEntry[] = [{ ...B, size: 4096 }];
      expect(diffManifests(expected, actual).changed).toEqual([]);
    });

    it('detects type and link target changes', () => {
      const expected = [LINK];
      const actual: ManifestEntry[] = [{ ...LINK, type: 'file', linkTarget: undefined }];
      const reasons = diffManifests(expected, actual).changed[0]?.reasons ?? [];
      expect(reasons).toContain('type');
      expect(reasons).toContain('link_target');
    });
  });
});
