import { createHash } from 'node:crypto';

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

function invalidKeyBlob(): Error {
  const err = new Error('[Internal] invalid key blob (base64 decode failed or empty)') as Error & {
    code?: string;
    kind?: string;
  };
  err.code = 'invalid_key_blob';
  err.kind = 'Internal';
  return err;
}

function decodeKeyBlob(keyBlob: string): Buffer {
  if (typeof keyBlob !== 'string' || !BASE64_RE.test(keyBlob)) throw invalidKeyBlob();
  const decoded = Buffer.from(keyBlob, 'base64');
  if (decoded.length === 0) throw invalidKeyBlob();
  return decoded;
}

/** keyBlob 是否为可解码的非空 base64。不抛。 */
export function isValidKeyBlob(keyBlob: string): boolean {
  try {
    decodeKeyBlob(keyBlob);
    return true;
  } catch {
    return false;
  }
}

/**
 * 与 OpenSSH `ssh-keygen -lf` 一致：SHA256(解码后的公钥 blob)，base64 并去掉末尾 '='，
 * 前缀 `SHA256:`。OpenSSH 指纹只由 blob 决定，算法名不参与计算。
 * blob 非法时抛 Error（code='invalid_key_blob', kind='Internal'）。
 */
export function fingerprintKey(keyBlob: string): string {
  const digest = createHash('sha256').update(decodeKeyBlob(keyBlob)).digest('base64').replace(/=+$/, '');
  return `SHA256:${digest}`;
}
