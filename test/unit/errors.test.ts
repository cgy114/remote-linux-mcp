import fc from 'fast-check';
import { describe, expect, it, vi } from 'vitest';
import {
  classify,
  classifyExit,
  formatToolError,
  stderrSignatures,
  toUserError,
} from '../../src/errors/classify.js';
import { errorTaxonomy, isRetryable, makeToolError } from '../../src/errors/taxonomy.js';
import type { ErrorFacts, ErrorKind, Logger, SshSignatures, ToolError } from '../../src/types.js';

const ERROR_KINDS: ErrorKind[] = [
  'Policy',
  'Internal',
  'Timeout',
  'HostKey',
  'SudoPrompt',
  'Auth',
  'DNS',
  'TCP',
  'RemoteExit',
  'Unknown',
];

// 从高到低的优先级顺序
const PRIORITY: ErrorKind[] = [
  'Policy',
  'Internal',
  'Timeout',
  'HostKey',
  'SudoPrompt',
  'Auth',
  'DNS',
  'TCP',
  'RemoteExit',
  'Unknown',
];

const NO_SIG: SshSignatures = {
  dns: false,
  tcp: false,
  auth: false,
  hostKeyUnknown: false,
  hostKeyChanged: false,
  sudoPrompt: false,
  connectionTimeout: false,
  other: [],
};

function sig(p: Partial<SshSignatures> = {}): SshSignatures {
  return { ...NO_SIG, ...p, other: p.other ?? [] };
}

/** 每个类别在"单独出现"时的最小事实片段。 */
const PARTS: Record<ErrorKind, { phase?: ErrorFacts['phase']; facts: Partial<ErrorFacts>; sig?: Partial<SshSignatures> }> = {
  Policy: { phase: 'config', facts: {} },
  Internal: { facts: { spawnError: { code: 'ENOENT', message: 'spawn ssh ENOENT' } } },
  Timeout: { facts: { timedOut: true } },
  HostKey: { facts: {}, sig: { hostKeyUnknown: true } },
  SudoPrompt: { facts: {}, sig: { sudoPrompt: true } },
  Auth: { facts: {}, sig: { auth: true } },
  DNS: { facts: {}, sig: { dns: true } },
  TCP: { facts: {}, sig: { tcp: true } },
  RemoteExit: { facts: { exitCode: 3, reason: 'remote_exit' } },
  Unknown: { facts: {} },
};

/** 合并多个类别的事实片段：phase 取 config（若含 Policy），signatures 做 OR 合并。 */
function combine(...kinds: ErrorKind[]): ErrorFacts {
  let facts: ErrorFacts = { phase: 'probe' };
  let merged: Partial<SshSignatures> = {};
  for (const k of kinds) {
    const part = PARTS[k];
    if (part.phase !== undefined) facts.phase = part.phase;
    facts = { ...facts, ...part.facts };
    merged = { ...merged, ...(part.sig ?? {}) };
  }
  facts.signatures = sig(merged);
  return facts;
}

function alone(kind: ErrorKind): ErrorFacts {
  return combine(kind);
}

describe('errorTaxonomy', () => {
  const expected: Record<ErrorKind, { code: string; retryable: boolean; exitCode: number }> = {
    Policy: { code: 'policy_denied', retryable: false, exitCode: 2 },
    Internal: { code: 'internal_error', retryable: false, exitCode: 1 },
    Timeout: { code: 'timeout', retryable: true, exitCode: 1 },
    HostKey: { code: 'host_key', retryable: false, exitCode: 4 },
    SudoPrompt: { code: 'sudo_prompt', retryable: false, exitCode: 4 },
    Auth: { code: 'auth_failed', retryable: false, exitCode: 4 },
    DNS: { code: 'dns_failed', retryable: true, exitCode: 4 },
    TCP: { code: 'tcp_failed', retryable: true, exitCode: 4 },
    RemoteExit: { code: 'remote_exit', retryable: false, exitCode: 1 },
    Unknown: { code: 'unknown', retryable: false, exitCode: 1 },
  };

  it.each(ERROR_KINDS)('%s has stable code/retryable/exitCode and a non-empty hint', (kind) => {
    const tax = errorTaxonomy(kind);
    expect(tax).toMatchObject(expected[kind]);
    expect(tax.hint.length).toBeGreaterThan(0);
  });

  it('HostKey hint is actionable (mentions remote-mcp trust <alias>)', () => {
    expect(errorTaxonomy('HostKey').hint).toContain('remote-mcp trust <alias>');
  });

  it('Auth hint mentions identity_file and ssh-add -l', () => {
    const hint = errorTaxonomy('Auth').hint;
    expect(hint).toContain('identity_file');
    expect(hint).toContain('ssh-add -l');
  });

  it('returns a copy, so mutating the result does not affect later calls', () => {
    const a = errorTaxonomy('Auth');
    a.code = 'mutated';
    expect(errorTaxonomy('Auth').code).toBe('auth_failed');
  });
});

describe('makeToolError', () => {
  it.each(ERROR_KINDS)('%s: defaults come from taxonomy, message is non-empty', (kind) => {
    const err = makeToolError(kind);
    const tax = errorTaxonomy(kind);
    expect(err.kind).toBe(kind);
    expect(err.code).toBe(tax.code);
    expect(err.retryable).toBe(tax.retryable);
    expect(err.hint).toBe(tax.hint);
    expect(err.message.length).toBeGreaterThan(0);
    expect(err).not.toHaveProperty('details');
  });

  it('detail.code overrides taxonomy code', () => {
    expect(makeToolError('HostKey', { code: 'host_key_pending' }).code).toBe('host_key_pending');
  });

  it('detail.message overrides default message', () => {
    expect(makeToolError('Auth', { message: 'custom' }).message).toBe('custom');
  });

  it('details are merged as given', () => {
    const err = makeToolError('RemoteExit', { details: { exitCode: 7, stderr: 'x' } });
    expect(err.details).toEqual({ exitCode: 7, stderr: 'x' });
  });
});

describe('isRetryable', () => {
  it.each(['trust', 'preflight'] as const)('DNS and TCP are not retryable in phase %s', (phase) => {
    expect(isRetryable('DNS', phase)).toBe(false);
    expect(isRetryable('TCP', phase)).toBe(false);
  });

  it.each(['jump', 'probe', 'verify', 'config'] as const)('DNS and TCP follow taxonomy in phase %s', (phase) => {
    expect(isRetryable('DNS', phase)).toBe(true);
    expect(isRetryable('TCP', phase)).toBe(true);
  });

  it('non-network kinds ignore phase and follow taxonomy', () => {
    for (const phase of ['trust', 'preflight', 'probe'] as const) {
      expect(isRetryable('Timeout', phase)).toBe(true);
      expect(isRetryable('Auth', phase)).toBe(false);
      expect(isRetryable('HostKey', phase)).toBe(false);
    }
  });
});

describe('classify priority', () => {
  it.each(ERROR_KINDS)('a single signal of %s classifies as %s', (kind) => {
    expect(classify(alone(kind))).toBe(kind);
  });

  // 相邻类别两两组合：较高优先级者必须胜出
  it.each(PRIORITY.slice(0, -1).map((hi, i) => [hi, PRIORITY[i + 1]] as const))(
    'adjacent pair %s > %s',
    (hi, lo) => {
      expect(classify(combine(hi, lo))).toBe(hi);
    },
  );

  it('all signals together classify as Policy', () => {
    expect(classify(combine(...PRIORITY))).toBe('Policy');
  });

  it('non-adjacent pairs also respect priority', () => {
    expect(classify(combine('Timeout', 'Auth'))).toBe('Timeout');
    expect(classify(combine('HostKey', 'TCP'))).toBe('HostKey');
    expect(classify(combine('Auth', 'RemoteExit'))).toBe('Auth');
  });

  it('hostKeyChanged and hostKeyUnknown both map to HostKey', () => {
    expect(classify({ phase: 'verify', signatures: sig({ hostKeyChanged: true }) })).toBe('HostKey');
    expect(classify({ phase: 'verify', signatures: sig({ hostKeyUnknown: true }) })).toBe('HostKey');
  });

  it.each(['not_registered', 'known_hosts_missing', 'fingerprint_mismatch'])(
    'reason %s maps to HostKey',
    (reason) => {
      expect(classify({ phase: 'trust', reason })).toBe('HostKey');
    },
  );

  it.each(['invalid_port', 'invalid_host', 'unknown_alias', 'policy_denied_cmd'])(
    'reason %s maps to Policy regardless of phase',
    (reason) => {
      expect(classify({ phase: 'probe', reason })).toBe('Policy');
    },
  );

  it('reason sudo_prompt maps to SudoPrompt', () => {
    expect(classify({ phase: 'probe', reason: 'sudo_prompt' })).toBe('SudoPrompt');
  });

  it('reason remote_exit maps to RemoteExit even without exitCode', () => {
    expect(classify({ phase: 'probe', reason: 'remote_exit' })).toBe('RemoteExit');
  });

  it('empty facts classify as Unknown', () => {
    expect(classify({ phase: 'probe' })).toBe('Unknown');
  });
});

describe('stderrSignatures with OpenSSH-style output', () => {
  const cases: Array<[string, keyof SshSignatures]> = [
    ['ssh: Could not resolve hostname bogus.invalid: Name or service not known', 'dns'],
    ['ssh: Could not resolve hostname db.internal: Temporary failure in name resolution', 'dns'],
    ['ssh: connect to host 10.0.0.5 port 22: Connection refused', 'tcp'],
    ['ssh: connect to host 10.0.0.5 port 22: No route to host', 'tcp'],
    ['ssh: connect to host 10.0.0.5 port 22: Network is unreachable', 'tcp'],
    ['kex_exchange_identification: read: Connection reset by peer', 'tcp'],
    ['Connection closed by 172.17.0.2 port 22', 'tcp'],
    ['deploy@172.17.0.2: Permission denied (publickey,password).', 'auth'],
    ['Received disconnect from 172.17.0.2 port 22:2: Too many authentication failures', 'auth'],
    ['Warning: Identity file /home/u/.ssh/id_x not accessible: No such file or directory.', 'other'],
    ['sign_and_send_pubkey: signing failed for ED25519 "/home/u/.ssh/id": agent refused operation', 'auth'],
    ['Host key verification failed.', 'hostKeyChanged'],
    [
      '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\nOffending ECDSA key in /root/.ssh/known_hosts:3',
      'hostKeyChanged',
    ],
    [
      "The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.\nED25519 key fingerprint is SHA256:abc.\nAre you sure you want to continue connecting (yes/no/[fingerprint])?",
      'hostKeyUnknown',
    ],
    ['sudo: a terminal is required to read the password; either use the -S option or configure an askpass helper', 'sudoPrompt'],
    ['sudo: no tty present and no askpass program specified', 'sudoPrompt'],
    ['[sudo] password for deploy:', 'sudoPrompt'],
    ['ssh: connect to host 10.0.0.5 port 22: Connection timed out', 'connectionTimeout'],
  ];

  it.each(cases)('matches %s', (stderr, flag) => {
    const sig = stderrSignatures(stderr);
    if (flag === 'other') {
      expect(sig.other.length).toBeGreaterThan(0);
      return;
    }
    expect(sig[flag]).toBe(true);
  });

  it('empty string yields all false and other []', () => {
    expect(stderrSignatures('')).toEqual(NO_SIG);
  });

  it('whitespace-only string yields other []', () => {
    expect(stderrSignatures('   \n\n  ').other).toEqual([]);
  });

  it('unknown text fills other with the last 3 non-empty lines', () => {
    const sig = stderrSignatures('l1\nl2\n\nl3\nl4\n');
    expect(sig.other).toEqual(['l2', 'l3', 'l4']);
    expect(sig.dns || sig.tcp || sig.auth || sig.hostKeyChanged || sig.hostKeyUnknown || sig.sudoPrompt || sig.connectionTimeout).toBe(false);
  });

  it('other lines are truncated to 300 characters', () => {
    const long = 'x'.repeat(1000);
    expect(stderrSignatures(long).other).toEqual(['x'.repeat(300)]);
  });

  it('other stays empty when a specific signature matched', () => {
    const sig = stderrSignatures('weird line\nConnection refused');
    expect(sig.tcp).toBe(true);
    expect(sig.other).toEqual([]);
  });

  it('matching is case-insensitive', () => {
    expect(stderrSignatures('PERMISSION DENIED (PUBLICKEY)').auth).toBe(true);
  });
});

describe('classifyExit', () => {
  const base = { exitCode: null, timedOut: false, signal: null } as const;

  it('spawnError -> {spawnError}', () => {
    const spawnError = { code: 'ENOENT', message: 'not found' };
    expect(classifyExit({ ...base, spawnError })).toEqual({ spawnError });
  });

  it('timedOut -> {timedOut: true}', () => {
    expect(classifyExit({ ...base, timedOut: true, exitCode: null })).toEqual({ timedOut: true });
  });

  it('timedOut wins over exit code', () => {
    expect(classifyExit({ ...base, timedOut: true, exitCode: 1 })).toEqual({ timedOut: true });
  });

  it('exit 255 -> ssh_transport_failure', () => {
    expect(classifyExit({ ...base, exitCode: 255 })).toEqual({ exitCode: 255, reason: 'ssh_transport_failure' });
  });

  it.each([1, 2, 127, 254])('exit %i -> remote_exit', (code) => {
    expect(classifyExit({ ...base, exitCode: code })).toEqual({ exitCode: code, reason: 'remote_exit' });
  });

  it('exit 0 -> {exitCode: 0}', () => {
    expect(classifyExit({ ...base, exitCode: 0 })).toEqual({ exitCode: 0 });
  });

  it('signal -> {signal}', () => {
    expect(classifyExit({ ...base, signal: 'SIGKILL' })).toEqual({ signal: 'SIGKILL' });
  });

  it('nothing known -> {}', () => {
    expect(classifyExit(base)).toEqual({});
  });

  it('exit 255 with auth stderr classifies as Auth; without it, Unknown', () => {
    const facts = (stderr: string): ErrorFacts => ({
      phase: 'probe',
      ...classifyExit({ ...base, exitCode: 255 }),
      signatures: stderrSignatures(stderr),
    });
    expect(classify(facts('Permission denied (publickey).'))).toBe('Auth');
    expect(classify(facts('something odd'))).toBe('Unknown');
  });

  it('exit 1-254 without signatures classifies as RemoteExit; exit 0 does not', () => {
    expect(classify({ phase: 'probe', ...classifyExit({ ...base, exitCode: 3 }) })).toBe('RemoteExit');
    expect(classify({ phase: 'probe', ...classifyExit({ ...base, exitCode: 0 }) })).toBe('Unknown');
  });
});

describe('toUserError', () => {
  it('returns the classified kind and taxonomy code', () => {
    const err = toUserError({ phase: 'verify', signatures: sig({ auth: true }) });
    expect(err.kind).toBe('Auth');
    expect(err.code).toBe('auth_failed');
  });

  it('puts exitCode, timedOut into details', () => {
    const err = toUserError({ phase: 'probe', exitCode: 3, reason: 'remote_exit', timedOut: false });
    expect(err.details).toMatchObject({ exitCode: 3 });
  });

  it('hint for not_registered is the trust command', () => {
    const err = toUserError({ phase: 'trust', reason: 'not_registered' });
    expect(err.kind).toBe('HostKey');
    expect(err.hint).toContain('remote-mcp trust <alias>');
  });

  it('hint for known_hosts_missing is the trust command', () => {
    expect(toUserError({ phase: 'trust', reason: 'known_hosts_missing' }).hint).toContain('remote-mcp trust <alias>');
  });

  it('hint for fingerprint_mismatch mentions trust and MITM risk', () => {
    const hint = toUserError({ phase: 'trust', reason: 'fingerprint_mismatch' }).hint ?? '';
    expect(hint).toContain('remote-mcp trust <alias>');
    expect(hint).toContain('中间人');
  });

  it('hint for unknown_alias points at config', () => {
    expect(toUserError({ phase: 'config', reason: 'unknown_alias' }).hint).toContain('配置');
  });

  it('falls back to taxonomy hint when reason has no specific guidance', () => {
    const err = toUserError({ phase: 'probe', signatures: sig({ tcp: true }) });
    expect(err.hint).toBe(errorTaxonomy('TCP').hint);
  });

  it('redacts ProxyCommand secrets from stderr', () => {
    const err = toUserError({
      phase: 'jump',
      signatures: sig({ dns: true }),
      stderr: 'ProxyCommand=ssh -W %h:%p secret-bastion\nCould not resolve hostname x',
    });
    const stderr = String(err.details?.['stderr']);
    expect(stderr).not.toContain('secret-bastion');
    expect(stderr).toContain('ProxyCommand=[REDACTED]');
  });

  it('keeps only the last 2000 characters of stderr', () => {
    const stderr = 'a'.repeat(3000) + 'TAIL';
    const err = toUserError({ phase: 'probe', stderr });
    const kept = String(err.details?.['stderr']);
    expect(kept.length).toBe(2000);
    expect(kept.endsWith('TAIL')).toBe(true);
  });

  it('never throws, even with malformed facts', () => {
    const weird = { phase: 'probe', reason: 42, signatures: null } as unknown as ErrorFacts;
    expect(() => toUserError(weird)).not.toThrow();
    expect(toUserError(weird).kind).toBe('Unknown');
  });

  it('a throwing logger does not break the result', () => {
    const log = {
      debug: () => {
        throw new Error('boom');
      },
    } as unknown as Logger;
    expect(() => toUserError({ phase: 'probe', timedOut: true }, log)).not.toThrow();
  });

  it('logs through the provided logger', () => {
    const debug = vi.fn();
    const log = { debug } as unknown as Logger;
    toUserError({ phase: 'probe', timedOut: true }, log);
    expect(debug).toHaveBeenCalledTimes(1);
  });
});

describe('formatToolError', () => {
  it('renders kind, code and message on the first line', () => {
    const err = makeToolError('Auth');
    expect(formatToolError(err).split('\n')[0]).toBe(`[Auth] auth_failed: ${err.message}`);
  });

  it('adds host line when alias is given and substitutes <alias> in hint', () => {
    const err = toUserError({ phase: 'trust', reason: 'not_registered' });
    const out = formatToolError(err, 'web1');
    expect(out).toContain('host: web1');
    expect(out).toContain('hint: 该主机尚未登记主机密钥。运行 `remote-mcp trust web1`');
    expect(out).not.toContain('<alias>');
  });

  it('omits host line without alias and keeps <alias> placeholder', () => {
    const out = formatToolError(toUserError({ phase: 'trust', reason: 'not_registered' }));
    expect(out).not.toContain('host:');
    expect(out).toContain('<alias>');
  });

  it('renders exitCode and indents redacted stderr tail', () => {
    const err = toUserError({
      phase: 'probe',
      exitCode: 2,
      reason: 'remote_exit',
      stderr: 'line one\nProxyCommand=ssh -W %h:%p hidden-host',
    });
    const out = formatToolError(err);
    expect(out).toContain('exitCode: 2');
    expect(out).toContain('stderr:\n  line one\n  ProxyCommand=[REDACTED]');
    expect(out).not.toContain('hidden-host');
  });

  it('shows timedOut flag', () => {
    expect(formatToolError(toUserError({ phase: 'probe', timedOut: true }))).toContain('timedOut: true');
  });

  it('does not render stderr when details lack it', () => {
    const err: ToolError = makeToolError('Timeout');
    expect(formatToolError(err)).not.toContain('stderr:');
  });
});

describe('property tests', () => {
  it('stderrSignatures never throws and other has at most 3 entries (arbitrary strings)', () => {
    fc.assert(
      fc.property(fc.oneof(fc.string(), fc.string({ unit: 'grapheme' }), fc.string({ unit: 'binary' })), (stderr) => {
        const sig = stderrSignatures(stderr);
        expect(sig.other.length).toBeLessThanOrEqual(3);
        for (const line of sig.other) {
          expect(line.length).toBeLessThanOrEqual(300);
        }
      }),
    );
  });

  const arbSig: fc.Arbitrary<SshSignatures> = fc.record({
    dns: fc.boolean(),
    tcp: fc.boolean(),
    auth: fc.boolean(),
    hostKeyUnknown: fc.boolean(),
    hostKeyChanged: fc.boolean(),
    sudoPrompt: fc.boolean(),
    connectionTimeout: fc.boolean(),
    other: fc.array(fc.string(), { maxLength: 5 }),
  });

  const arbFacts: fc.Arbitrary<ErrorFacts> = fc.record(
    {
      phase: fc.constantFrom('trust', 'preflight', 'jump', 'probe', 'verify', 'config'),
      exitCode: fc.option(fc.oneof(fc.integer({ min: -5, max: 300 }), fc.constant(null)), { nil: undefined }),
      timedOut: fc.option(fc.boolean(), { nil: undefined }),
      signal: fc.option(fc.oneof(fc.constant(null), fc.constantFrom('SIGTERM', 'SIGKILL', '')), { nil: undefined }),
      stderr: fc.option(fc.string(), { nil: undefined }),
      spawnError: fc.option(fc.record({ code: fc.string(), message: fc.string() }), { nil: undefined }),
      signatures: fc.option(arbSig, { nil: undefined }),
      reason: fc.option(
        fc.constantFrom(
          'not_registered',
          'known_hosts_missing',
          'fingerprint_mismatch',
          'invalid_port',
          'unknown_alias',
          'policy_x',
          'sudo_prompt',
          'remote_exit',
          'ssh_transport_failure',
          'zzz',
        ),
        { nil: undefined },
      ),
    },
    { requiredKeys: ['phase'] },
  );

  it('classify never throws and returns a legal ErrorKind for any facts combination', () => {
    fc.assert(
      fc.property(arbFacts, (facts) => {
        const kind = classify(facts);
        expect(ERROR_KINDS).toContain(kind);
      }),
    );
  });

  it('toUserError never throws and yields a legal kind', () => {
    fc.assert(
      fc.property(arbFacts, (facts) => {
        const err = toUserError(facts);
        expect(ERROR_KINDS).toContain(err.kind);
        expect(typeof err.retryable).toBe('boolean');
      }),
    );
  });

  it('classifyExit never throws for arbitrary exit data', () => {
    fc.assert(
      fc.property(
        fc.record({
          exitCode: fc.oneof(fc.integer(), fc.constant(null)),
          timedOut: fc.boolean(),
          signal: fc.oneof(fc.constant(null), fc.string()),
          spawnError: fc.option(fc.record({ code: fc.string(), message: fc.string() }), { nil: undefined }),
        }),
        (run) => {
          expect(() => classify({ phase: 'probe', ...classifyExit(run) })).not.toThrow();
        },
      ),
    );
  });

  it('isRetryable returns a boolean for all kind/phase pairs', () => {
    const phases = ['trust', 'preflight', 'jump', 'probe', 'verify', 'config'] as const;
    fc.assert(
      fc.property(fc.constantFrom(...ERROR_KINDS), fc.constantFrom(...phases), (kind, phase) => {
        expect(typeof isRetryable(kind, phase)).toBe('boolean');
      }),
    );
  });
});
