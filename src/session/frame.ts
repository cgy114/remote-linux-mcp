import { randomBytes } from 'node:crypto';
import { encodeScript } from '../policy/remote-command.js';
import {
  MARKER_MAGIC,
  MAX_CARRY_BYTES,
  NONCE_HEX_LENGTH,
  RS,
  SESSION_ID_PREFIX,
  US,
} from './constants.js';
import type {
  Frame,
  FrameEvent,
  FrameParseErrorCode,
  FrameParseResult,
  FrameParser,
} from './types.js';

const NONCE_RE = new RegExp(`^[0-9a-f]{${NONCE_HEX_LENGTH}}$`);

/** 生成 32 个小写十六进制字符的会话 nonce（16 字节随机数）。 */
export function createNonce(): string {
  return randomBytes(NONCE_HEX_LENGTH / 2).toString('hex');
}

/** 生成 `sess_<32 hex>` 形式的会话 id。 */
export function newSessionId(): string {
  return `${SESSION_ID_PREFIX}${randomBytes(NONCE_HEX_LENGTH / 2).toString('hex')}`;
}

/**
 * 解析帧体：`RDY` / `B:<seq>` / `E:<seq>:<rc>`。
 * seq 与 rc 均为非负安全整数；其余（含空体、前导/尾随字节）一律非法。
 */
function parseBody(body: Buffer): Frame | undefined {
  const text = body.toString('latin1');
  if (text === 'RDY') return { type: 'RDY' };

  const begin = /^B:(\d+)$/.exec(text);
  if (begin !== null) {
    const seq = Number(begin[1]);
    if (Number.isSafeInteger(seq)) return { type: 'B', seq };
    return undefined;
  }

  const end = /^E:(\d+):(\d+)$/.exec(text);
  if (end !== null) {
    const seq = Number(end[1]);
    const rc = Number(end[2]);
    if (Number.isSafeInteger(seq) && Number.isSafeInteger(rc)) return { type: 'E', seq, rc };
    return undefined;
  }

  return undefined;
}

/**
 * 创建增量帧解析器。
 *
 * 标记形如 `RS "RMCP" <nonce> ":" <body> US`。切分点任意：
 * - 尚未凑齐的标记前缀留在 carry，等下一次 push；
 * - 完整比较后不匹配的 RS 只当作一个普通数据字节，其余字节继续扫描；
 * - 标记完整但迟迟没有 US，且候选（从 RS 起）超过 MAX_CARRY_BYTES -> frame_too_long；
 * - 帧体非法 -> bad_frame。
 *
 * 错误是粘滞的：返回错误后解析器不再接受输入。
 */
export function createFrameParser(nonce: string): FrameParser {
  if (typeof nonce !== 'string' || !NONCE_RE.test(nonce)) {
    throw new TypeError(`nonce must be ${NONCE_HEX_LENGTH} lowercase hex characters`);
  }

  const prefix = Buffer.concat([
    Buffer.from([RS]),
    Buffer.from(`${MARKER_MAGIC}${nonce}:`, 'ascii'),
  ]);
  const prefixBodyOffset = prefix.length;

  let carry = Buffer.alloc(0);
  let failed: FrameParseErrorCode | undefined;

  /** 比较候选起始处与完整标记前缀：完全匹配 / 仍可能是前缀 / 已不匹配。 */
  const relation = (candidate: Buffer, limit: number): 'full' | 'partial' | 'mismatch' => {
    const n = Math.min(limit, prefix.length);
    for (let i = 0; i < n; i++) {
      if (candidate[i] !== prefix[i]) return 'mismatch';
    }
    return limit >= prefix.length ? 'full' : 'partial';
  };

  const push = (chunk: Buffer | Uint8Array): FrameParseResult => {
    if (failed !== undefined) return { events: [], error: failed };

    const chunkBuf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    const buf = carry.length === 0 ? chunkBuf : Buffer.concat([carry, chunkBuf]);
    const events: FrameEvent[] = [];

    // 把相邻的数据字节合并成一个 data 事件，避免逐字节事件膨胀。
    let dataStart = -1;
    let dataEnd = -1;
    const queueData = (from: number, to: number): void => {
      if (to <= from) return;
      if (dataStart < 0) {
        dataStart = from;
        dataEnd = to;
        return;
      }
      if (from === dataEnd) {
        dataEnd = to;
        return;
      }
      events.push({ type: 'data', buf: buf.subarray(dataStart, dataEnd) });
      dataStart = from;
      dataEnd = to;
    };
    const flushData = (): void => {
      if (dataStart >= 0) events.push({ type: 'data', buf: buf.subarray(dataStart, dataEnd) });
      dataStart = -1;
      dataEnd = -1;
    };

    let pos = 0;
    let carryFrom = -1;
    let error: FrameParseErrorCode | undefined;

    while (pos < buf.length) {
      const idx = buf.indexOf(RS, pos);
      if (idx === -1) {
        queueData(pos, buf.length);
        pos = buf.length;
        break;
      }
      queueData(pos, idx);

      const available = buf.length - idx;
      const rel = relation(buf.subarray(idx), available);
      if (rel === 'partial') {
        carryFrom = idx;
        break;
      }
      if (rel === 'mismatch') {
        // 只有 RS 本身是数据；后续字节重新扫描，可能藏着真正的标记。
        queueData(idx, idx + 1);
        pos = idx + 1;
        continue;
      }

      const bodyStart = idx + prefixBodyOffset;
      const usIdx = buf.indexOf(US, bodyStart);
      if (usIdx === -1) {
        if (available > MAX_CARRY_BYTES) {
          error = 'frame_too_long';
        } else {
          carryFrom = idx;
        }
        break;
      }

      const frame = parseBody(buf.subarray(bodyStart, usIdx));
      if (frame === undefined) {
        error = 'bad_frame';
        break;
      }
      flushData();
      events.push({ type: 'frame', frame });
      pos = usIdx + 1;
    }

    flushData();

    if (error !== undefined) {
      carry = Buffer.alloc(0);
      failed = error;
      return { events, error };
    }

    // 复制剩余字节，避免 subarray 长期持有大 chunk。
    carry = carryFrom >= 0 ? Buffer.from(buf.subarray(carryFrom)) : Buffer.alloc(0);
    return { events };
  };

  return {
    push,
    get failed(): FrameParseErrorCode | undefined {
      return failed;
    },
  };
}

/**
 * 编码一条命令协议行：`<seq> <encodeScript(command)>\n`。
 * encodeScript 保证 payload 为单行 ASCII（换行等一律写成 `\xHH`）。
 */
export function encodeCommandLine(seq: number, command: string): string {
  if (!Number.isSafeInteger(seq) || seq < 0) {
    throw new RangeError('seq must be a non-negative safe integer');
  }
  if (typeof command !== 'string') {
    throw new TypeError('command must be a string');
  }
  return `${seq} ${encodeScript(command)}\n`;
}

/** 关闭会话的协议行。 */
export function encodeCloseLine(): string {
  return 'Q\n';
}
