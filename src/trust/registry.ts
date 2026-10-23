import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { ConfigError, TrustError } from '../errors/classes.js';
import { assertAlias } from '../policy/alias.js';
import type { PinnedHostKey, TrustRegistry } from '../types.js';
import { atomicWriteFile, ensureDir, isErrnoCode, readTextIfExists } from '../util/fsx.js';
import { sleep } from '../util/time.js';
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
  if (fingerprintKey(pin.keyBlob) !== pin.fingerprint) {
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

/** 创建锁并返回本次持有的唯一 token；已存在（EEXIST）返回 undefined。 */
async function tryCreateLock(file: string): Promise<string | undefined> {
  let handle;
  try {
    handle = await fs.open(file, 'wx');
  } catch (err) {
    if (isErrnoCode(err, 'EEXIST')) return undefined;
    throw err;
  }
  const token = randomUUID();
  try {
    await handle.writeFile(
      JSON.stringify({ pid: process.pid, token, time: new Date().toISOString() }),
      'utf8',
    );
  } catch (err) {
    await handle.close().catch(() => undefined);
    await fs.unlink(file).catch(() => undefined);
    throw err;
  }
  await handle.close();
  return token;
}

/** 读取并解析锁记录；ENOENT / 非 JSON / 非对象时返回 undefined。 */
async function readLockRecord(file: string): Promise<Record<string, unknown> | undefined> {
  let text: string;
  try {
    text = await fs.readFile(file, 'utf8');
  } catch (err) {
    if (isErrnoCode(err, 'ENOENT')) return undefined;
    throw err;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return undefined;
  }
  return isPlainObject(parsed) ? parsed : undefined;
}

/**
 * 把为校验而移走的锁尽量放回原路径；目标已存在或恢复失败时保留临时名。
 * 宁可留下一个临时文件，也不覆盖或删除不属于自己的锁。
 */
async function restoreMoved(moved: string, file: string): Promise<void> {
  try {
    await fs.access(file);
    return; // 目标已存在：保留临时名
  } catch (err) {
    if (!isErrnoCode(err, 'ENOENT')) return;
  }
  try {
    await fs.rename(moved, file);
  } catch {
    // 保留临时名（例如 Windows 上目标刚被创建，rename 不会覆盖）
  }
}

/**
 * 锁文件陈旧则原子回收并返回 true；锁已不存在也返回 true（立即重试）。
 * 先读取 token 与 mtime，再 rename 到唯一临时名，之后复核被移走文件的 token：
 * 只有确认移走的仍是判定时那把陈旧锁才 unlink；期间被替换为新锁则尝试放回，返回 false。
 */
async function removeIfStale(file: string, staleMs: number): Promise<boolean> {
  let text: string;
  let mtimeMs: number;
  try {
    text = await fs.readFile(file, 'utf8');
    mtimeMs = (await fs.stat(file)).mtimeMs;
  } catch (err) {
    if (isErrnoCode(err, 'ENOENT')) return true;
    throw err;
  }

  let record: unknown;
  try {
    record = JSON.parse(text);
  } catch {
    record = undefined;
  }
  const tokenBefore = isPlainObject(record) ? record['token'] : undefined;

  if (Date.now() - mtimeMs <= staleMs) return false;

  const reclaimed = `${file}.reclaim-${randomUUID()}`;
  try {
    await fs.rename(file, reclaimed);
  } catch (err) {
    if (isErrnoCode(err, 'ENOENT')) return true;
    throw err;
  }

  let movedText: string;
  try {
    movedText = await fs.readFile(reclaimed, 'utf8');
  } catch (err) {
    if (isErrnoCode(err, 'ENOENT')) return true;
    throw err;
  }
  let movedRecord: unknown;
  try {
    movedRecord = JSON.parse(movedText);
  } catch {
    movedRecord = undefined;
  }
  const tokenAfter = isPlainObject(movedRecord) ? movedRecord['token'] : undefined;

  // 可解析时比较 token；坏锁则比较原文。一致说明移走的仍是判定时的陈旧锁。
  const same = tokenBefore !== undefined ? tokenAfter === tokenBefore : movedText === text;
  if (same) {
    try {
      await fs.unlink(reclaimed);
    } catch (err) {
      if (!isErrnoCode(err, 'ENOENT')) throw err;
    }
    return true;
  }

  // 判定后锁已被新持有者替换：放回原路径，放弃本次回收。
  await restoreMoved(reclaimed, file);
  return false;
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

  let token: string | undefined;
  for (;;) {
    token = await tryCreateLock(file);
    if (token !== undefined) break;
    if (await removeIfStale(file, staleMs)) continue;
    if (Date.now() >= deadline) {
      throw new TrustError('lock_busy', `无法获取信任锁（${timeoutMs}ms 超时）：${file}`);
    }
    await sleep(LOCK_POLL_MS + Math.random() * LOCK_JITTER_MS);
  }

  const heldToken = token;
  let released = false;
  return async () => {
    if (released) return;
    released = true;

    // 1) 读取并解析；只有 token 仍是本次持有者时才继续。
    const current = await readLockRecord(file);
    if (current === undefined || current.token !== heldToken) return;

    // 2) 原子移走，避免 unlink 掉在此期间被替换的新锁。
    const moved = `${file}.release-${heldToken}`;
    try {
      await fs.rename(file, moved);
    } catch (err) {
      if (isErrnoCode(err, 'ENOENT')) return;
      throw err;
    }

    // 3) 复核被移走的文件：内容已更换则恢复，绝不删除别人的锁。
    const checked = await readLockRecord(moved);
    if (checked !== undefined && checked.token === heldToken) {
      try {
        await fs.unlink(moved);
      } catch (err) {
        if (!isErrnoCode(err, 'ENOENT')) throw err;
      }
      return;
    }
    await restoreMoved(moved, file);
  };
}
