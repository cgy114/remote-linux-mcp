import { describe, expect, it } from 'vitest';
import { redactAuditRecord, redactAuditText } from '../../../src/audit/redact.js';
import { createLogger } from '../../../src/log.js';

const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const GITHUB_TOKEN = `ghp_${'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'}`;
const OPENAI_KEY = 'sk-proj-abcdefghijklmnopqrstuvwxyz012345';
const ANTHROPIC_KEY = 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345';
const BEARER = 'Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature';
const PEM =
  '-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZS1rZXktbWF0ZXJpYWw=\n-----END OPENSSH PRIVATE KEY-----';

const FIXTURES = [
  `aws=${AWS_KEY}`,
  `github=${GITHUB_TOKEN}`,
  `openai=${OPENAI_KEY}`,
  `anthropic=${ANTHROPIC_KEY}`,
  BEARER,
  'password=hunter2',
  'token: "abc123"',
  'secret=topsecret',
  'api_key=xyz789',
  PEM,
  'https://alice:pa55word@example.com/repo',
  'ssh -o ProxyCommand="ssh -W %h:%p jump" host',
];

const CANARIES = [
  AWS_KEY,
  GITHUB_TOKEN,
  OPENAI_KEY,
  ANTHROPIC_KEY,
  'eyJhbGciOiJIUzI1NiJ9',
  'hunter2',
  'abc123',
  'topsecret',
  'xyz789',
  'ZmFrZS1rZXktbWF0ZXJpYWw',
  'alice:pa55word',
  'ssh -W %h:%p jump',
];

describe('redactAuditText', () => {
  it('redacts every fixture form', () => {
    const out = redactAuditText(FIXTURES.join('\n'));
    for (const canary of CANARIES) {
      expect(out, `leaked ${canary}`).not.toContain(canary);
    }
    expect(out).toContain('[REDACTED PRIVATE KEY]');
    expect(out).toContain('ProxyCommand=[REDACTED]');
    expect(out).toContain('https://[REDACTED]@example.com/repo');
    expect(out).toContain('Bearer [REDACTED]');
  });

  it('leaves ordinary text unchanged', () => {
    const text = 'alias=web1 exit=0 duration_ms=42';
    expect(redactAuditText(text)).toBe(text);
  });

  it.each([
    ['aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'wJalrXUtnFEMI'],
    ['AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'wJalrXUtnFEMI'],
    ['aws_session_token=FwoGZXIvYXdzEBYaDexample', 'FwoGZXIvYXdzEBYaDexample'],
    ['AWS_SESSION_TOKEN: FwoGZXIvYXdzEBYaDexample', 'FwoGZXIvYXdzEBYaDexample'],
    ['aws_access_key_id=AKIAIOSFODNN7EXAMPLE', 'AKIAIOSFODNN7EXAMPLE'],
    ['AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE', 'AKIAIOSFODNN7EXAMPLE'],
    ['my_api_key=xyz789', 'xyz789'],
    ['db_password: hunter2', 'hunter2'],
    ['client_secret = s3cr3t-value', 's3cr3t-value'],
    ['refresh_token="rt-abc123"', 'rt-abc123'],
  ])('redacts AWS/generic assignment %j', (text, canary) => {
    const out = redactAuditText(text);
    expect(out).toContain('[REDACTED]');
    expect(out, `leaked ${canary}`).not.toContain(canary);
  });

  it('keeps the key name while replacing the value', () => {
    expect(redactAuditText('aws_secret_access_key=abc123')).toBe(
      'aws_secret_access_key=[REDACTED]',
    );
    expect(redactAuditText('AWS_SECRET_ACCESS_KEY: abc123')).toBe(
      'AWS_SECRET_ACCESS_KEY:[REDACTED]',
    );
  });

  it('does not mistake hashes, fingerprints or ordinary hex for secrets', () => {
    const text =
      'commandSha256=deadbeef0123456789 ' +
      'SHA256:abc123def456 ' +
      'fingerprint=0011aabbccdd ' +
      'sha256=deadbeef';
    expect(redactAuditText(text)).toBe(text);
  });
});

describe('redactAuditRecord', () => {
  it('recurses through objects and arrays and redacts sensitive keys', () => {
    const input = {
      alias: 'web1',
      password: 'hunter2',
      nested: {
        apiKey: 'k-1',
        message: 'token=abc123',
        list: [{ secret: 's' }, { ok: true }],
      },
    };
    const out = redactAuditRecord(input) as Record<string, unknown>;

    expect(out['alias']).toBe('web1');
    expect(out['password']).toBe('[REDACTED]');
    const nested = out['nested'] as Record<string, unknown>;
    expect(nested['apiKey']).toBe('[REDACTED]');
    expect(nested['message']).toBe('token=[REDACTED]');
    expect(nested['list']).toEqual([{ secret: '[REDACTED]' }, { ok: true }]);
  });

  it('handles circular references', () => {
    const input: Record<string, unknown> = { ok: 1 };
    input['self'] = input;
    const out = redactAuditRecord(input) as Record<string, unknown>;
    expect(out['self']).toBe('[Circular]');
    expect(out['ok']).toBe(1);
  });

  it('does not mutate the input', () => {
    const input = { password: 'hunter2', nested: { token: 'abc' } };
    redactAuditRecord(input);
    expect(input).toEqual({ password: 'hunter2', nested: { token: 'abc' } });
  });

  it('redacts the same fixtures inside nested strings', () => {
    const out = redactAuditRecord({ detail: FIXTURES.join('\n') }) as { detail: string };
    for (const canary of CANARIES) {
      expect(out.detail).not.toContain(canary);
    }
  });
});

describe('logger redaction', () => {
  it('applies the same patterns to log lines', () => {
    const chunks: string[] = [];
    const stream = {
      write(chunk: string | Uint8Array): boolean {
        chunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
        return true;
      },
    } as unknown as NodeJS.WritableStream;
    const log = createLogger({ level: 'info', stream });

    log.info({ detail: FIXTURES.join('\n') }, `error: ${FIXTURES.join(' ')}`);

    const text = chunks.join('\n');
    expect(text.length).toBeGreaterThan(0);
    for (const canary of CANARIES) {
      expect(text, `log leaked ${canary}`).not.toContain(canary);
    }
  });
});
