import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { encodeScript } from '../../src/policy/remote-command.js';
import { RS, US } from '../../src/session/constants.js';
import {
  createFrameParser,
  createNonce,
  encodeCloseLine,
  encodeCommandLine,
  newSessionId,
} from '../../src/session/frame.js';
import type { Frame, FrameEvent, FrameParseResult } from '../../src/session/types.js';

const NONCE = '0123456789abcdef0123456789abcdef';
const OTHER_NONCE = 'fedcba9876543210fedcba9876543210';

function marker(nonce: string, body: string): Buffer {
  return Buffer.concat([
    Buffer.from([RS]),
    Buffer.from(`RMCP${nonce}:`, 'ascii'),
    Buffer.from(body, 'ascii'),
    Buffer.from([US]),
  ]);
}

function markerPrefix(nonce: string): Buffer {
  return Buffer.concat([Buffer.from([RS]), Buffer.from(`RMCP${nonce}:`, 'ascii')]);
}

function dataOf(events: FrameEvent[]): Buffer {
  return Buffer.concat(events.filter((e) => e.type === 'data').map((e) => (e as { buf: Buffer }).buf));
}

function framesOf(events: FrameEvent[]): Frame[] {
  return events.filter((e) => e.type === 'frame').map((e) => (e as { frame: Frame }).frame);
}

function collect(results: FrameParseResult[]): {
  data: Buffer;
  frames: Frame[];
  error?: string;
} {
  const data: Buffer[] = [];
  const frames: Frame[] = [];
  let error: string | undefined;
  for (const r of results) {
    for (const e of r.events) {
      if (e.type === 'data') data.push(e.buf);
      else frames.push(e.frame);
    }
    error ??= r.error;
  }
  return { data: Buffer.concat(data), frames, ...(error !== undefined ? { error } : {}) };
}

/** 逐字节送入，断言与一次性解析一致。 */
function parseBytewise(bytes: Buffer): ReturnType<typeof collect> {
  const parser = createFrameParser(NONCE);
  const results: FrameParseResult[] = [];
  for (let i = 0; i < bytes.length; i++) results.push(parser.push(bytes.subarray(i, i + 1)));
  return collect(results);
}

type Segment =
  | { kind: 'data'; bytes: Buffer }
  | { kind: 'frame'; body: string; frame: Frame };

const frameSegment: fc.Arbitrary<Segment> = fc.oneof(
  fc.constant<Segment>({ kind: 'frame', body: 'RDY', frame: { type: 'RDY' } }),
  fc.integer({ min: 0, max: 1_000_000 }).map(
    (seq): Segment => ({ kind: 'frame', body: `B:${seq}`, frame: { type: 'B', seq } }),
  ),
  fc
    .tuple(fc.integer({ min: 0, max: 1_000_000 }), fc.integer({ min: 0, max: 255 }))
    .map(
      ([seq, rc]): Segment => ({
        kind: 'frame',
        body: `E:${seq}:${rc}`,
        frame: { type: 'E', seq, rc },
      }),
    ),
);

// 随机数据不过滤 RS：末尾的 RS 会留在 carry，由最终 flush() 作为数据吐出。
const rawDataSegment: fc.Arbitrary<Segment> = fc.uint8Array({ maxLength: 40 }).map(
  (arr): Segment => ({ kind: 'data', bytes: Buffer.from(arr) }),
);

// 显式的伪前缀/内嵌分隔符。刻意只取远短于完整标记的前缀，避免随机后续字节
// 恰好补全标记（那属于帧，不应当作数据）。
const prefix = markerPrefix(NONCE);
const pseudoDataSegments: Segment[] = [
  { kind: 'data', bytes: Buffer.from([RS]) },
  { kind: 'data', bytes: Buffer.from([RS, 0x52]) },
  { kind: 'data', bytes: Buffer.from(prefix.subarray(0, 6)) },
  { kind: 'data', bytes: Buffer.from(prefix.subarray(0, 12)) },
  { kind: 'data', bytes: Buffer.from([0x61, RS, 0x62, US, 0x63]) },
];

const dataSegment: fc.Arbitrary<Segment> = fc.oneof(
  rawDataSegment,
  fc.constantFrom(...pseudoDataSegments),
);

const segmentArb: fc.Arbitrary<Segment> = fc.oneof(dataSegment, frameSegment);

function buildStream(segments: Segment[]): {
  bytes: Buffer;
  data: Buffer;
  frames: Frame[];
} {
  const wire: Buffer[] = [];
  const data: Buffer[] = [];
  const frames: Frame[] = [];
  for (const s of segments) {
    if (s.kind === 'data') {
      wire.push(s.bytes);
      data.push(s.bytes);
    } else {
      wire.push(marker(NONCE, s.body));
      frames.push(s.frame);
    }
  }
  return { bytes: Buffer.concat(wire), data: Buffer.concat(data), frames };
}

function sliceAt(buf: Buffer, cuts: number[]): Buffer[] {
  const points = [...new Set(cuts.filter((c) => c >= 0 && c <= buf.length))].sort((a, b) => a - b);
  const out: Buffer[] = [];
  let prev = 0;
  for (const p of points) {
    out.push(buf.subarray(prev, p));
    prev = p;
  }
  out.push(buf.subarray(prev));
  return out;
}

describe('createNonce / newSessionId', () => {
  it('creates 32 lowercase hex nonces', () => {
    const a = createNonce();
    const b = createNonce();
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(b).toMatch(/^[0-9a-f]{32}$/);
    expect(a).not.toBe(b);
  });

  it('creates sess_<32 hex> ids', () => {
    expect(newSessionId()).toMatch(/^sess_[0-9a-f]{32}$/);
    expect(newSessionId()).not.toBe(newSessionId());
  });
});

describe('createFrameParser', () => {
  it('rejects malformed nonces', () => {
    for (const bad of ['', 'abc', 'A'.repeat(32), 'g'.repeat(32), '0'.repeat(31), '0'.repeat(33)]) {
      expect(() => createFrameParser(bad)).toThrow(TypeError);
    }
  });

  it('parses data and all three frame types', () => {
    const wire = Buffer.concat([
      Buffer.from('before'),
      marker(NONCE, 'RDY'),
      Buffer.from('between'),
      marker(NONCE, 'B:7'),
      marker(NONCE, 'E:7:0'),
      Buffer.from('after'),
    ]);
    const { data, frames, error } = collect([createFrameParser(NONCE).push(wire)]);
    expect(error).toBeUndefined();
    expect(data.toString()).toBe('beforebetweenafter');
    expect(frames).toEqual([
      { type: 'RDY' },
      { type: 'B', seq: 7 },
      { type: 'E', seq: 7, rc: 0 },
    ]);
  });

  it('accepts frames without any newline', () => {
    const wire = Buffer.concat([marker(NONCE, 'RDY'), marker(NONCE, 'B:0'), marker(NONCE, 'E:0:255')]);
    expect(wire.includes(0x0a)).toBe(false);
    const { frames, error } = collect([createFrameParser(NONCE).push(wire)]);
    expect(error).toBeUndefined();
    expect(frames).toEqual([
      { type: 'RDY' },
      { type: 'B', seq: 0 },
      { type: 'E', seq: 0, rc: 255 },
    ]);
  });

  it('parses identically when split at every byte offset and byte-by-byte', () => {
    const wire = Buffer.concat([
      Buffer.from('pre:'),
      marker(NONCE, 'RDY'),
      Buffer.from([RS]),
      Buffer.from('[31m'),
      marker(NONCE, 'B:1'),
      Buffer.from('mid'),
      marker(NONCE, 'E:1:3'),
      Buffer.from('post'),
    ]);
    const expected = {
      data: Buffer.concat([
        Buffer.from('pre:'),
        Buffer.from([RS]),
        Buffer.from('[31m'),
        Buffer.from('mid'),
        Buffer.from('post'),
      ]),
      frames: [
        { type: 'RDY' as const },
        { type: 'B' as const, seq: 1 },
        { type: 'E' as const, seq: 1, rc: 3 },
      ],
    };

    for (let split = 0; split <= wire.length; split++) {
      const parser = createFrameParser(NONCE);
      const got = collect([parser.push(wire.subarray(0, split)), parser.push(wire.subarray(split))]);
      expect(got.error).toBeUndefined();
      expect(got.data.equals(expected.data)).toBe(true);
      expect(got.frames).toEqual(expected.frames);
    }

    const bytewise = parseBytewise(wire);
    expect(bytewise.error).toBeUndefined();
    expect(bytewise.data.equals(expected.data)).toBe(true);
    expect(bytewise.frames).toEqual(expected.frames);
  });

  it('keeps embedded RS and US bytes as data', () => {
    const wire = Buffer.from([0x61, RS, 0x62, US, 0x63]);
    const { data, frames, error } = collect([createFrameParser(NONCE).push(wire)]);
    expect(error).toBeUndefined();
    expect(frames).toEqual([]);
    expect(data.equals(wire)).toBe(true);
  });

  it('treats a complete marker with the wrong nonce as data', () => {
    const wire = Buffer.concat([
      Buffer.from('a'),
      marker(OTHER_NONCE, 'RDY'),
      Buffer.from('b'),
    ]);
    const { data, frames, error } = collect([createFrameParser(NONCE).push(wire)]);
    expect(error).toBeUndefined();
    expect(frames).toEqual([]);
    expect(data.equals(wire)).toBe(true);
  });

  it('treats a near-miss prefix (mismatch at the colon) as data', () => {
    const wire = Buffer.concat([
      Buffer.from([RS]),
      Buffer.from(`RMCP${NONCE}XRDY`, 'ascii'),
      Buffer.from([US]),
    ]);
    const { data, frames, error } = collect([createFrameParser(NONCE).push(wire)]);
    expect(error).toBeUndefined();
    expect(frames).toEqual([]);
    expect(data.equals(wire)).toBe(true);
  });

  it('holds an incomplete prefix in carry, then releases it as data on mismatch', () => {
    const parser = createFrameParser(NONCE);
    const partial = markerPrefix(NONCE).subarray(0, 20);
    const first = parser.push(partial);
    expect(first.error).toBeUndefined();
    expect(first.events).toEqual([]);

    const second = parser.push(Buffer.from('X'));
    expect(second.error).toBeUndefined();
    expect(second.events).toHaveLength(1);
    expect(second.events[0]!.type).toBe('data');
    expect(Buffer.concat([partial, Buffer.from('X')]).equals(dataOf(second.events))).toBe(true);
  });

  it('flushes a trailing RS held in carry when the stream ends', () => {
    const parser = createFrameParser(NONCE);
    const first = parser.push(Buffer.from('hello'));
    expect(dataOf(first.events).toString()).toBe('hello');

    const second = parser.push(Buffer.from([RS]));
    expect(second.error).toBeUndefined();
    expect(second.events).toEqual([]);

    const flushed = parser.flush();
    expect(flushed).toHaveLength(1);
    expect(flushed[0]!.type).toBe('data');
    expect(dataOf(flushed).equals(Buffer.from([RS]))).toBe(true);
    expect(parser.flush()).toEqual([]);
  });

  it('flushes an incomplete marker prefix as data', () => {
    const parser = createFrameParser(NONCE);
    const partial = markerPrefix(NONCE).subarray(0, 20);
    expect(parser.push(partial).events).toEqual([]);

    const flushed = parser.flush();
    expect(flushed).toHaveLength(1);
    expect(dataOf(flushed).equals(partial)).toBe(true);
    expect(parser.flush()).toEqual([]);
  });

  it('flushes nothing after a parse error', () => {
    const parser = createFrameParser(NONCE);
    expect(parser.push(marker(NONCE, 'bad body')).error).toBe('bad_frame');
    expect(parser.flush()).toEqual([]);
  });

  it('keeps a partial prefix across many chunks', () => {
    const parser = createFrameParser(NONCE);
    const prefix = markerPrefix(NONCE);
    const results: FrameParseResult[] = [];
    for (let i = 0; i < prefix.length; i++) results.push(parser.push(prefix.subarray(i, i + 1)));
    results.push(parser.push(marker(NONCE, 'RDY').subarray(prefix.length)));
    const got = collect(results);
    expect(got.error).toBeUndefined();
    expect(got.data.length).toBe(0);
    expect(got.frames).toEqual([{ type: 'RDY' }]);
  });

  it('emits no events for empty chunks and still parses afterwards', () => {
    const parser = createFrameParser(NONCE);
    expect(parser.push(Buffer.alloc(0))).toEqual({ events: [] });
    expect(parser.push(new Uint8Array(0))).toEqual({ events: [] });
    const r = parser.push(marker(NONCE, 'RDY'));
    expect(r.error).toBeUndefined();
    expect(framesOf(r.events)).toEqual([{ type: 'RDY' }]);
  });

  it('treats a large all-RS buffer as data only', () => {
    // 末尾的 RS 仍是潜在标记前缀，追加一个非 RS 字节把它释放为数据。
    const wire = Buffer.concat([Buffer.alloc(5000, RS), Buffer.from('x')]);
    const { data, frames, error } = collect([createFrameParser(NONCE).push(wire)]);
    expect(error).toBeUndefined();
    expect(frames).toEqual([]);
    expect(data.length).toBe(wire.length);
    expect(data.equals(wire)).toBe(true);

    const parser = createFrameParser(NONCE);
    const split = collect([
      parser.push(wire.subarray(0, 1234)),
      parser.push(wire.subarray(1234, 4999)),
      parser.push(wire.subarray(4999)),
    ]);
    expect(split.error).toBeUndefined();
    expect(split.frames).toEqual([]);
    expect(split.data.equals(wire)).toBe(true);
  });

  it('rejects an invalid frame body with bad_frame and retains prior data', () => {
    const parser = createFrameParser(NONCE);
    const r = parser.push(Buffer.concat([Buffer.from('ok'), marker(NONCE, 'NOPE')]));
    expect(r.error).toBe('bad_frame');
    expect(dataOf(r.events).toString()).toBe('ok');
    expect(framesOf(r.events)).toEqual([]);
    expect(parser.failed).toBe('bad_frame');
  });

  it.each(['', 'R', 'RDY ', 'B:', 'B:x', 'B:-1', 'B:1:2', 'E:1', 'E:1:', 'E:x:0', 'e:1:0'])(
    'rejects malformed body %j',
    (body) => {
      const r = createFrameParser(NONCE).push(marker(NONCE, body));
      expect(r.error).toBe('bad_frame');
      expect(r.events).toEqual([]);
    },
  );

  it('rejects seq/rc outside the safe integer range', () => {
    for (const body of ['B:9007199254740992', 'E:9007199254740992:0', 'E:1:9007199254740992']) {
      const r = createFrameParser(NONCE).push(marker(NONCE, body));
      expect(r.error).toBe('bad_frame');
    }
  });

  it('errors with frame_too_long when an unterminated candidate exceeds 4096 bytes', () => {
    const prefix = markerPrefix(NONCE);
    const wire = Buffer.concat([prefix, Buffer.alloc(4097 - prefix.length, 0x78)]);
    const r = createFrameParser(NONCE).push(wire);
    expect(r.error).toBe('frame_too_long');
    expect(r.events).toEqual([]);
  });

  it('holds exactly 4096 candidate bytes without error, then rejects the body', () => {
    const prefix = markerPrefix(NONCE);
    const parser = createFrameParser(NONCE);
    const first = parser.push(Buffer.concat([prefix, Buffer.alloc(4096 - prefix.length, 0x78)]));
    expect(first.error).toBeUndefined();
    expect(first.events).toEqual([]);
    expect(parser.failed).toBeUndefined();

    const second = parser.push(Buffer.from([US]));
    expect(second.error).toBe('bad_frame');
    expect(parser.failed).toBe('bad_frame');
  });

  it('is sticky after an error', () => {
    const parser = createFrameParser(NONCE);
    expect(parser.push(marker(NONCE, 'bad body')).error).toBe('bad_frame');
    const after = parser.push(marker(NONCE, 'RDY'));
    expect(after).toEqual({ events: [], error: 'bad_frame' });
  });

  it('streams data incrementally before a marker prefix arrives', () => {
    const parser = createFrameParser(NONCE);
    const first = parser.push(Buffer.from('hello'));
    expect(dataOf(first.events).toString()).toBe('hello');
    const second = parser.push(marker(NONCE, 'RDY'));
    expect(framesOf(second.events)).toEqual([{ type: 'RDY' }]);
  });

  it('reassembles data byte-for-byte under arbitrary segment order and chunking', () => {
    fc.assert(
      fc.property(
        fc.array(segmentArb, { maxLength: 12 }),
        fc.array(fc.nat({ max: 5000 }), { maxLength: 20 }),
        (segments, cuts) => {
          const { bytes, data, frames } = buildStream(segments);
          const chunks = sliceAt(bytes, cuts);
          const parser = createFrameParser(NONCE);
          const results: FrameParseResult[] = [];
          for (const chunk of chunks) results.push(parser.push(chunk));
          // 流结束：carry 里的不完整前缀属于数据。
          const flushed = parser.flush();
          if (flushed.length > 0) results.push({ events: flushed });
          const got = collect(results);

          expect(got.error).toBeUndefined();
          expect(got.frames).toEqual(frames);
          expect(got.data.equals(data)).toBe(true);
        },
      ),
      { numRuns: 200 },
    );
  });

  it('is invariant to chunk boundaries for a fixed mixed stream', () => {
    const segments: Segment[] = [
      { kind: 'data', bytes: Buffer.from('alpha') },
      { kind: 'frame', body: 'RDY', frame: { type: 'RDY' } },
      { kind: 'frame', body: 'B:42', frame: { type: 'B', seq: 42 } },
      { kind: 'data', bytes: Buffer.from([0x80, 0xff, 0x00]) },
      { kind: 'frame', body: 'E:42:1', frame: { type: 'E', seq: 42, rc: 1 } },
    ];
    const { bytes, data, frames } = buildStream(segments);
    for (const step of [1, 2, 3, 7, 13, 37, bytes.length]) {
      const parser = createFrameParser(NONCE);
      const results: FrameParseResult[] = [];
      for (let i = 0; i < bytes.length; i += step) {
        results.push(parser.push(bytes.subarray(i, Math.min(bytes.length, i + step))));
      }
      const got = collect(results);
      expect(got.error).toBeUndefined();
      expect(got.frames).toEqual(frames);
      expect(got.data.equals(data)).toBe(true);
    }
  });
});

describe('encodeCommandLine', () => {
  function decodePayload(payload: string): Buffer {
    const out: number[] = [];
    for (let i = 0; i < payload.length; ) {
      if (payload[i] === '\\' && payload[i + 1] === 'x') {
        out.push(Number.parseInt(payload.slice(i + 2, i + 4), 16));
        i += 4;
      } else {
        out.push(payload.charCodeAt(i));
        i += 1;
      }
    }
    return Buffer.from(out);
  }

  it('emits "<seq> <payload>\\n" with a single line of printable ASCII', () => {
    const command = 'echo "hi" $HOME\nprintf \'ok\'';
    const line = encodeCommandLine(7, command);
    expect(line).toBe(`7 ${encodeScript(command)}\n`);
    expect(line.endsWith('\n')).toBe(true);
    expect(line.slice(0, -1)).not.toMatch(/[\r\n]/);
    expect(line.slice(0, -1)).toMatch(/^[\x20-\x7e]*$/);
    const payload = line.slice(2, -1);
    expect(decodePayload(payload).equals(Buffer.from(command, 'utf8'))).toBe(true);
  });

  it('round-trips arbitrary commands byte-for-byte', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 200 }), fc.integer({ min: 0, max: 1_000_000 }), (command, seq) => {
        const line = encodeCommandLine(seq, command);
        expect(line.startsWith(`${seq} `)).toBe(true);
        expect(line.endsWith('\n')).toBe(true);
        expect(line.slice(0, -1)).not.toMatch(/[\r\n]/);
        expect(decodePayload(line.slice(`${seq} `.length, -1)).equals(Buffer.from(command, 'utf8'))).toBe(
          true,
        );
      }),
      { numRuns: 200 },
    );
  });

  it('rejects invalid seq values', () => {
    for (const seq of [-1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => encodeCommandLine(seq, 'x')).toThrow(RangeError);
    }
  });

  it('encodes the close line', () => {
    expect(encodeCloseLine()).toBe('Q\n');
  });
});
