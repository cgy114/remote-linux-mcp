import { afterEach, describe, expect, it, vi } from 'vitest';
import { childLogger, createLogger, redact, serializeError } from '../../src/log.js';

function memoryStream(): { stream: NodeJS.WritableStream; chunks: string[] } {
  const chunks: string[] = [];
  const stream = {
    write(chunk: string | Uint8Array): boolean {
      chunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
      return true;
    },
  } as unknown as NodeJS.WritableStream;
  return { stream, chunks };
}

describe('createLogger', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('writes one JSON object per line to the given stream', () => {
    const { stream, chunks } = memoryStream();
    const log = createLogger({ level: 'debug', stream, bindings: { component: 'test' } });
    log.info({ alias: 'web1' }, 'hello');
    log.warn('plain message');

    expect(chunks).toHaveLength(2);
    const first = JSON.parse(chunks[0]!.trimEnd()) as Record<string, unknown>;
    expect(first['level']).toBe('info');
    expect(first['msg']).toBe('hello');
    expect(first['component']).toBe('test');
    expect(first['alias']).toBe('web1');
    expect(typeof first['time']).toBe('string');
    expect(new Date(first['time'] as string).toISOString()).toBe(first['time']);

    const second = JSON.parse(chunks[1]!.trimEnd()) as Record<string, unknown>;
    expect(second['level']).toBe('warn');
    expect(second['msg']).toBe('plain message');
  });

  it('filters by level', () => {
    const { stream, chunks } = memoryStream();
    const log = createLogger({ level: 'warn', stream });
    log.debug('d');
    log.info('i');
    log.error('e');
    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toContain('"level":"error"');
  });

  it('never writes to stdout', () => {
    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const { stream } = memoryStream();
    const log = createLogger({ level: 'debug', stream });
    log.debug('a');
    log.info('b');
    log.warn('c');
    log.error('d');
    expect(stdoutSpy).not.toHaveBeenCalled();
  });

  it('defaults to stderr when no stream is given', () => {
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const log = createLogger({ level: 'info' });
    log.info('to stderr');
    expect(stderrSpy).toHaveBeenCalledTimes(1);
    expect(stdoutSpy).not.toHaveBeenCalled();
  });

  it('redacts secret keys in bindings and fields', () => {
    const { stream, chunks } = memoryStream();
    const log = createLogger({ level: 'info', stream, bindings: { apiKey: 'k1' } });
    log.info({ password: 'pw', nested: { Authorization: 'Bearer x', ok: 1 } }, 'm');
    const line = JSON.parse(chunks[0]!.trimEnd()) as Record<string, unknown>;
    expect(line['apiKey']).toBe('[REDACTED]');
    expect(line['password']).toBe('[REDACTED]');
    expect((line['nested'] as Record<string, unknown>)['Authorization']).toBe('[REDACTED]');
    expect((line['nested'] as Record<string, unknown>)['ok']).toBe(1);
    expect(chunks[0]).not.toContain('Bearer x');
  });
});

describe('childLogger', () => {
  it('merges bindings into child output', () => {
    const { stream, chunks } = memoryStream();
    const parent = createLogger({ level: 'info', stream, bindings: { a: 1 } });
    const child = childLogger(parent, { b: 2 });
    child.info({ c: 3 }, 'x');
    const line = JSON.parse(chunks[0]!.trimEnd()) as Record<string, unknown>;
    expect(line).toMatchObject({ a: 1, b: 2, c: 3, msg: 'x' });
  });
});

describe('redact', () => {
  it('recurses into nested objects and arrays and matches key patterns', () => {
    const input = {
      user: 'bob',
      privateKey: 'PEM',
      list: [{ api_key: 'a' }, { 'x-token': 'b' }, { passwd: 'c' }],
      deep: { secret: { inner: 1 } },
      'Api-Key': 'z',
    };
    const out = redact(input) as Record<string, unknown>;
    expect(out['user']).toBe('bob');
    expect(out['privateKey']).toBe('[REDACTED]');
    expect(out['list']).toEqual([{ api_key: '[REDACTED]' }, { 'x-token': '[REDACTED]' }, { passwd: '[REDACTED]' }]);
    expect(out['deep']).toEqual({ secret: '[REDACTED]' });
    expect(out['Api-Key']).toBe('[REDACTED]');
  });

  it('replaces unquoted ProxyCommand values through end of line (no leaking of args)', () => {
    const s = 'ssh -o ProxyCommand=ssh -W %h:%p bastion host1';
    expect(redact(s)).toBe('ssh -o ProxyCommand=[REDACTED]');
  });

  it('replaces quoted ProxyCommand values', () => {
    const s = `-o ProxyCommand="ssh -W %h:%p jump" -p 22`;
    expect(redact(s)).toBe(`-o ProxyCommand=[REDACTED] -p 22`);
  });

  it('returns [Circular] for cyclic references', () => {
    const a: Record<string, unknown> = { name: 'a' };
    a['self'] = a;
    const out = redact(a) as Record<string, unknown>;
    expect(out['name']).toBe('a');
    expect(out['self']).toBe('[Circular]');
  });

  it('does not treat shared (non-cyclic) references as circular', () => {
    const shared = { v: 1 };
    const out = redact({ x: shared, y: shared }) as Record<string, unknown>;
    expect(out['x']).toEqual({ v: 1 });
    expect(out['y']).toEqual({ v: 1 });
  });

  it('accepts extra key names to redact', () => {
    expect(redact({ host: 'h', custom: 'c' }, ['custom'])).toEqual({ host: 'h', custom: '[REDACTED]' });
  });
});

describe('serializeError', () => {
  it('captures name, message, code and stack', () => {
    const e = Object.assign(new Error('boom'), { code: 'E_X' });
    const out = serializeError(e);
    expect(out.name).toBe('Error');
    expect(out.message).toBe('boom');
    expect(out.code).toBe('E_X');
    expect(typeof out.stack).toBe('string');
  });

  it('truncates stack to 4KB', () => {
    const e = new Error('big');
    e.stack = 'x'.repeat(10_000);
    const out = serializeError(e);
    expect(out.stack!.endsWith('...[truncated]')).toBe(true);
    // 4096 字节原文 + 截断标记
    expect(Buffer.byteLength(out.stack!, 'utf8')).toBeLessThanOrEqual(4096 + '...[truncated]'.length);
  });

  it('serializes cause one level deep and redacts it', () => {
    const inner = new Error('inner', { cause: new Error('deepest') });
    (inner as Error & { stack?: string }).stack = 'inner-stack';
    const outer = new Error('outer', { cause: inner });
    const out = serializeError(outer);
    const cause = out.cause as Record<string, unknown>;
    expect(cause['message']).toBe('inner');
    expect(cause['cause']).toBeUndefined();
  });

  it('redacts ProxyCommand in message', () => {
    const out = serializeError(new Error('failed: -o ProxyCommand=evil --x'));
    expect(out.message).toBe('failed: -o ProxyCommand=[REDACTED]');
  });
});
