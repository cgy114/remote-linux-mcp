import { trimIncompleteTail, trimLeadingPartial } from '../ssh/runner.js';
import type { CapturedOutput, OutputCapture, OutputEncoding } from './types.js';

const UTF8_FATAL = new TextDecoder('utf-8', { fatal: true });

/** 把会话 nonce 的唯一可见形式替换为占位符；未提供 nonce 时原样返回。 */
export function redactNonce(text: string, nonce: string | undefined): string {
  if (nonce === undefined || nonce.length === 0) return text;
  return text.split(nonce).join('<nonce>');
}

/** 合法 UTF-8 且不含 NUL 才按文本返回；否则按 base64 保真返回。 */
function detectEncoding(buf: Buffer): OutputEncoding {
  if (buf.includes(0)) return 'base64';
  try {
    UTF8_FATAL.decode(buf);
    return 'utf-8';
  } catch {
    return 'base64';
  }
}

/**
 * 创建有界输出捕获：保留头部 floor(maxBytes/2) 与尾部其余字节，
 * 中间丢弃但持续累计总字节数。ANSI 转义与二进制内容原样保留。
 */
export function createOutputCapture(maxBytes: number, nonce?: string): OutputCapture {
  if (!Number.isInteger(maxBytes) || maxBytes < 1) {
    throw new RangeError('maxBytes must be a positive integer');
  }

  const headCap = Math.floor(maxBytes / 2);
  const tailCap = maxBytes - headCap;

  let headChunks: Buffer[] = [];
  let headLen = 0;
  let tailChunks: Buffer[] = [];
  let tailLen = 0;
  let total = 0;
  let finished: CapturedOutput | undefined;

  const push = (chunk: Buffer | Uint8Array): void => {
    if (finished !== undefined) throw new Error('output capture is already finished');
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (buf.length === 0) return;
    total += buf.length;

    let rest = buf;
    if (headLen < headCap) {
      const take = Math.min(headCap - headLen, rest.length);
      headChunks.push(rest.subarray(0, take));
      headLen += take;
      rest = rest.subarray(take);
    }
    if (rest.length > 0) {
      tailChunks.push(rest);
      tailLen += rest.length;
      // 尾部最多保留 2*tailCap，超出后压实，保证内存有界。
      if (tailLen > tailCap * 2) {
        const merged = Buffer.concat(tailChunks, tailLen);
        tailChunks = [merged.subarray(merged.length - tailCap)];
        tailLen = tailCap;
      }
    }
  };

  const finish = (): CapturedOutput => {
    if (finished !== undefined) return finished;

    const head = Buffer.concat(headChunks, headLen);
    const tailAll = Buffer.concat(tailChunks, tailLen);
    const truncated = total > maxBytes;

    let kept: Buffer;
    if (!truncated) {
      // total <= maxBytes 时 head + tail 即完整内容。
      kept = tailLen === 0 ? head : Buffer.concat([head, tailAll], headLen + tailLen);
    } else {
      const tail = tailAll.subarray(Math.max(0, tailAll.length - tailCap));
      // 头尾拼接处可能切断多字节字符：各自修剪，避免伪 U+FFFD。
      kept = Buffer.concat([trimIncompleteTail(head), trimLeadingPartial(tail)]);
    }

    const encoding = detectEncoding(kept);
    finished = {
      text:
        encoding === 'utf-8'
          ? redactNonce(kept.toString('utf8'), nonce)
          : kept.toString('base64'),
      encoding,
      truncated,
      bytes: total,
    };
    return finished;
  };

  return {
    push,
    finish,
    get bytes(): number {
      return total;
    },
    get truncated(): boolean {
      return total > maxBytes;
    },
  };
}
