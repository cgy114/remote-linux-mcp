import { describe, expect, it } from 'vitest';
import {
  hasRedirection,
  hasUnsafeConstruct,
  leadingWords,
  normalizeSkeleton,
  splitSegments,
  stripLeadingNoise,
  tokenize,
} from '../../../src/policy/command-scan.js';

describe('tokenize', () => {
  it('removes quotes and backslash escapes', () => {
    expect(tokenize(`r''m -rf /`)).toEqual(['rm', '-rf', '/']);
    expect(tokenize(String.raw`\rm -rf /`)).toEqual(['rm', '-rf', '/']);
    expect(tokenize(`echo "a b" 'c d'`)).toEqual(['echo', 'a b', 'c d']);
  });
});

describe('normalizeSkeleton', () => {
  it('removes empty quote pairs', () => {
    expect(normalizeSkeleton(`r''m -rf /`)).toBe('rm -rf /');
    expect(normalizeSkeleton(`r""m -rf /`)).toBe('rm -rf /');
    expect(normalizeSkeleton(`r''''m -rf /`)).toBe('rm -rf /');
  });

  it('removes leading and escaping backslashes and line continuations', () => {
    expect(normalizeSkeleton(String.raw`\rm -rf /`)).toBe('rm -rf /');
    expect(normalizeSkeleton('rm \\\n-rf /')).toBe('rm -rf /');
  });

  it('expands $IFS and ${IFS}', () => {
    expect(normalizeSkeleton('rm${IFS}-rf${IFS}/')).toBe('rm -rf /');
    expect(normalizeSkeleton('rm$IFS-rf$IFS/')).toBe('rm -rf /');
  });

  it('collapses horizontal whitespace but keeps newlines as separators', () => {
    expect(normalizeSkeleton('  ls   -la  ')).toBe('ls -la');
    expect(normalizeSkeleton('ls\n\nrm -rf /')).toBe('ls\nrm -rf /');
  });
});

describe('splitSegments', () => {
  it('splits on all supported separators', () => {
    const segments = splitSegments('a; b && c || d | e & f\ng');
    expect(segments.map((s) => s.text)).toEqual(['a', 'b', 'c', 'd', 'e', 'f', 'g']);
    expect(segments.map((s) => s.separator)).toEqual([';', '&&', '||', '|', '&', '\n', '']);
  });

  it('is quote-aware', () => {
    const segments = splitSegments(`echo "a;b" 'c|d' && ls`);
    expect(segments.map((s) => s.text)).toEqual([`echo "a;b" 'c|d'`, 'ls']);
  });

  it('marks command substitution, backticks and process substitution unsafe', () => {
    expect(splitSegments('echo $(id)').some((s) => s.unsafe)).toBe(true);
    expect(splitSegments('echo `id`').some((s) => s.unsafe)).toBe(true);
    expect(splitSegments('cat <(id)').some((s) => s.unsafe)).toBe(true);
    expect(splitSegments('ls').some((s) => s.unsafe)).toBe(false);
  });

  it('marks unclosed quotes unsafe', () => {
    expect(splitSegments(`echo "unterminated`)[0]?.unsafe).toBe(true);
    expect(splitSegments(`echo 'unterminated`)[0]?.unsafe).toBe(true);
  });

  it('marks function definitions unsafe', () => {
    expect(splitSegments('f() { echo x; }').some((s) => s.unsafe)).toBe(true);
    expect(splitSegments('function f { echo x; }').some((s) => s.unsafe)).toBe(true);
  });

  it('does not treat quoted operators as separators', () => {
    expect(splitSegments(`ls ">"`).map((s) => s.text)).toEqual([`ls ">"`]);
  });
});

describe('leadingWords', () => {
  it('skips environment assignments and command/builtin wrappers', () => {
    expect(leadingWords('FOO=1 BAR=2 ls -la', 2)).toEqual(['ls', '-la']);
    expect(leadingWords('command ls -la', 1)).toEqual(['ls']);
    expect(leadingWords('builtin -p cd /tmp', 2)).toEqual(['cd', '/tmp']);
  });

  it('removes quotes and backslash escapes', () => {
    expect(leadingWords(`r''m -rf /`, 2)).toEqual(['rm', '-rf']);
    expect(leadingWords(String.raw`\rm -rf /`, 1)).toEqual(['rm']);
  });

  it('returns at most n words', () => {
    expect(leadingWords('a b c d', 2)).toEqual(['a', 'b']);
    expect(leadingWords('a b', 0)).toEqual([]);
  });
});

describe('hasUnsafeConstruct', () => {
  it.each([
    'echo $(id)',
    'echo `id`',
    'cat <(id)',
    'cat >(id)',
    'eval "$X"',
    'source /tmp/x',
    '. /tmp/x',
    'alias ls=rm',
    'set -x',
    'export FOO=1',
    'unset PATH',
    'trap "echo x" EXIT',
    'f() { echo x; }',
  ])('flags %j', (command) => {
    expect(hasUnsafeConstruct(command)).toBe(true);
  });

  it.each(['echo hi', 'ls -la', 'grep "eval" notes.txt', `echo '$(id)'`])(
    'does not flag %j',
    (command) => {
      expect(hasUnsafeConstruct(command)).toBe(false);
    },
  );

  it('checks every segment of a compound string', () => {
    expect(hasUnsafeConstruct('ls; eval x')).toBe(true);
    expect(hasUnsafeConstruct('ls && export FOO=1')).toBe(true);
  });
});

describe('stripLeadingNoise', () => {
  it('removes env assignments, command/builtin wrappers and shell keywords', () => {
    expect(stripLeadingNoise('FOO=1 command -p rm -rf /')).toBe('rm -rf /');
    expect(stripLeadingNoise('builtin rm -rf /')).toBe('rm -rf /');
    expect(stripLeadingNoise('then rm -rf /')).toBe('rm -rf /');
    expect(stripLeadingNoise('if true')).toBe('true');
    expect(stripLeadingNoise('! ls')).toBe('ls');
  });

  it('does not mangle commands sharing a keyword prefix', () => {
    expect(stripLeadingNoise('ifconfig eth0')).toBe('ifconfig eth0');
    expect(stripLeadingNoise('donesomething')).toBe('donesomething');
  });
});

describe('hasRedirection', () => {
  it.each(['ls > out', 'ls >> out', 'cat < in', 'cat <<EOF', 'ls 2>&1'])('flags %j', (cmd) => {
    expect(hasRedirection(cmd)).toBe(true);
  });

  it.each([`echo ">"`, `echo '>>'`, 'ls -la'])('does not flag %j', (cmd) => {
    expect(hasRedirection(cmd)).toBe(false);
  });
});
