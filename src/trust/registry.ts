import path from 'node:path';
import { promises as fs } from 'node:fs';
import { ConfigError, TrustError } from '../errors/classes.js';
import { assertAlias } from '../policy/alias.js';
import type { PinnedHostKey, TrustRegistry } from '../types.js';
import { atomicWriteFile, ensureDir, isErrnoCode, readTextIfExists } from '../util/fsx.js';
import { fingerprintKey, isValidKeyBlob } from './fingerprint.js';

const PIN_KEYS: readonly string[] = ['algorithm', 'keyBlob', 'fingerprint', 'firstSeenAt', 'lastVerifiedAt'];
const REGISTRY_KEYS: readonly string[] = ['version', 'hosts'];
const FINGERPRINT_RE = /^SHA256:[A-Za-z0-9+/]+$/;

const LOCK_POLL_MS = 50;
const LOCK_JITTER_MS = 25;
const DEFAULT_LOCK_STALE_MS = 30_000;
const DEFAULT_LOCK_TIMEOUT_MS = 5_000;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function schemaError(file: string, message: string): ConfigError {
  return new ConfigError('schema', `invalid trust registry (${message}): ${file}`, { path: file });
}

function validatePinned(file: string, alias: string, value: unknown): PinnedHostKey {
  const where = `hosts.${alias}`;
  if (!isPlainObject(value)) throw schemaError(file, `${where} must be an object`);
  for (const k of Object.keys(value)) {
    if (!PIN_KEYS.includes(k)) throw schemaError(file, `${where} has unknown field "${k}"`);
  }
  for (const k of PIN_KEYS) {
    const v = value[k];
    if (typeof v !== 'string' || v === '') throw schemaError(file, `${where}.${k} missing or invalid`);
  }
  const pin = value as unknown as PinnedHostKey;
  if (!FINGERPRINT_RE.test(pin.fingerprint)) throw schemaError(file, `${where}.fingerprint has invalid format`);
  if (!isValidKeyBlob(pin.keyBlob)) throw schemaError(file, `${where}.keyBlob is not valid base64`);
  if (fingerprintKey(pin.algorithm, pin.keyBlob) !== pin.fingerprint) {
    throw schemaError(file, `${where}.fingerprint does not match keyBlob`);
  }
  return {
    algorithm: pin.algorithm,
    keyBlob: pin.keyBlob,
    fingerprint: pin.fingerprint,
    firstSeenAt: pin.firstSeenAt,
    lastVerifiedAt: pin.lastVerifiedAt,
  };
}

/** 严格校验：只接受 {version:1, hosts:{[alias]: PinnedHostKey}}，不允许多余字段。返回新对象。 */
function validateRegistry(file: string, raw: unknown): TrustRegistry {
  if (!isPlainObject(raw)) throw schemaError(file, 'top level must be an object');
  for (const k of Object.keys(raw)) {
    if (!REGISTRY_KEYS.includes(k)) throw schemaError(file, `unknown top-level field "${k}"`);
  }
  if (raw['version'] !== 1) throw schemaError(file, 'version must be 1');
  const hostsRaw = raw['hosts'];
  if (!isPlainObject(hostsRaw)) throw schemaError(file, 'hosts must be an object');

  const hosts: Record<string, PinnedHostKey> = {};
  for (const alias of Object.keys(hostsRaw)) {
    let safe: string;
    try {
      safe = assertAlias(alias);
    } catch {
      throw schemaError(file, `invalid alias "${alias}"`);
    }
    if (safe === '__proto__') throw schemaError(file, 'invalid alias "__proto__"');
    hosts[safe] = validatePinned(file, safe, hostsRaw[alias]);
  }
  return { version: 1, hosts };
}

/**
 * 读取信任注册表。ENOENT -> 空注册表；JSON 解析失败 -> ConfigError('parse')；
 * 结构非法 -> ConfigError('schema')。其他读错误 -> ConfigError('io')。
 */
export async function loadTrustRegistry(file: string): Promise<TrustRegistry> {
  let text: string | undefined;
  try {
    text = await readTextIfExists(file);
  } catch (err) {
    throw new ConfigError('io', `cannot read trust registry: ${file}`, { path: file, cause: err });
  }
  if (text === undefined) return { version: 1, hosts: {} };

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new ConfigError('parse', `trust registry is not valid JSON: ${file}`, { path: file, cause: err });
  }
  return validateRegistry(file, parsed);
}

/** 校验后以 JSON（2 空格缩进，末尾换行）原子写入。 */
export async function saveTrustRegistry(file: string, reg: TrustRegistry): Promise<void> {
  const valid = validateRegistry(file, reg);
  await ensureDir(path.dirname(file));
  await atomicWriteFile(file, JSON.stringify(valid, null, 2) + '\n');
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function tryCreateLock(file: string): Promise<boolean> {
  let handle;
  try {
    handle = await fs.open(file, 'wx');
  } catch (err) {
    if (isErrnoCode(err, 'EEXIST')) return false;
    throw err;
  }
  try {
    await handle.writeFile(JSON.stringify({ pid: process.pid, time: new Date().toISOString() }), 'utf8');
  } catch (err) {
    await handle.close().catch(() => undefined);
    await fs.unlink(file).catch(() => undefined);
    throw err;
  }
  await handle.close();
  return true;
}

/** 锁文件陈旧则删除并返回 true；锁已不存在也返回 true（立即重试）。 */
async function removeIfStale(file: string, staleMs: number): Promise<boolean> {
  let mtimeMs: number;
  try {
    mtimeMs = (await fs.stat(file)).mtimeMs;
  } catch (err) {
    if (isErrnoCode(err, 'ENOENT')) return true;
    throw err;
  }
  if (Date.now() - mtimeMs <= staleMs) return false;
  try {
    await fs.unlink(file);
  } catch (err) {
    if (!isErrnoCode(err, 'ENOENT')) throw err;
  }
  return true;
}

/**
 * 获取信任锁（O_EXCL）。忙则每 50ms+抖动轮询；超过 timeoutMs（默认 5000）抛 TrustError('lock_busy')。
 * 超过 staleMs（默认 30000）的陈旧锁会被回收。返回幂等的 release。
 */
export async function acquireTrustLock(
  file: string,
  opts?: { staleMs?: number; timeoutMs?: number },
): Promise<() => Promise<void>> {
  const staleMs = opts?.staleMs ?? DEFAULT_LOCK_STALE_MS;
  const timeoutMs = opts?.timeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS;
  await ensureDir(path.dirname(file));
  const deadline = Date.now() + timeoutMs;

  for (;;) {
    if (await tryCreateLock(file)) break;
    if (await removeIfStale(file, staleMs)) continue;
    if (Date.now() >= deadline) {
      throw new TrustError('lock_busy', `无法获取信任锁（${timeoutMs}ms 超时）：${file}`);
    }
    await sleep(LOCK_POLL_MS + Math.random() * LOCK_JITTER_MS);
  }

  let released = false;
  return async () => {
    if (released) return;
    released = true;
    try {
      await fs.unlink(file);
    } catch (err) {
      if (!isErrnoCode(err, 'ENOENT')) throw err;
    }
  };
}
