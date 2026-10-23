import path from 'node:path';
import { promises as fs } from 'node:fs';
import { ConfigError } from '../errors/classes.js';
import { spawnCapture } from '../ssh/runner.js';
import type { KnownHostEntry } from '../types.js';
import { atomicWriteFile, ensureDir, isErrnoCode, readTextIfExists } from '../util/fsx.js';
import { isValidKeyBlob } from './fingerprint.js';

const KEYGEN_TIMEOUT_MS = 10_000;
const KEYGEN_MAX_OUTPUT_BYTES = 64 * 1024;
const MARKERS: ReadonlySet<string> = new Set(['@cert-authority', '@revoked']);

function isSkippable(trimmed: string): boolean {
  return trimmed === '' || trimmed.startsWith('#');
}

/**
 * 解析单行 known_hosts。空行/注释返回 null；非法行返回 null（不抛）。
 * 格式：[marker] <hosts> <algorithm> <base64> [comment...]；hosts 按逗号拆分。
 * 哈希主机名 `|1|...` 无法反解：保留为 hosts=[原串]。
 */
export function parseKnownHostsLine(line: string, lineNo: number): KnownHostEntry | null {
  const trimmed = line.trim();
  if (isSkippable(trimmed)) return null;

  const tokens = trimmed.split(/\s+/);
  let marker: KnownHostEntry['marker'] = null;
  const first = tokens[0];
  if (first === undefined) return null;
  if (first.startsWith('@')) {
    if (!MARKERS.has(first)) return null;
    marker = first as KnownHostEntry['marker'];
    tokens.shift();
  }

  const [hostsField, algorithm, keyBlob] = tokens;
  if (hostsField === undefined || algorithm === undefined || keyBlob === undefined) return null;

  const hosts = hostsField.startsWith('|1|')
    ? [hostsField]
    : hostsField.split(',').filter((h) => h.length > 0);
  if (hosts.length === 0) return null;
  if (!isValidKeyBlob(keyBlob)) return null;

  return { marker, hosts, algorithm, keyBlob, raw: line, line: lineNo };
}

/**
 * 读取并逐行解析 known_hosts。
 * - ENOENT -> 空结果（与 tolerant 无关）。
 * - 其他读错误：tolerant（默认 true）-> 空结果且 invalidLines=[0]；tolerant=false -> ConfigError('io')。
 */
export async function readKnownHosts(
  file: string,
  opts?: { tolerant?: boolean },
): Promise<{ entries: KnownHostEntry[]; invalidLines: number[] }> {
  const tolerant = opts?.tolerant ?? true;
  let text: string;
  try {
    text = await fs.readFile(file, 'utf8');
  } catch (err) {
    if (isErrnoCode(err, 'ENOENT')) return { entries: [], invalidLines: [] };
    if (tolerant) return { entries: [], invalidLines: [0] };
    throw new ConfigError('io', `cannot read known_hosts: ${file}`, { path: file, cause: err });
  }

  const entries: KnownHostEntry[] = [];
  const invalidLines: number[] = [];
  text.split(/\r?\n/).forEach((line, index) => {
    const lineNo = index + 1;
    if (isSkippable(line.trim())) return;
    const entry = parseKnownHostsLine(line, lineNo);
    if (entry === null) invalidLines.push(lineNo);
    else entries.push(entry);
  });
  return { entries, invalidLines };
}

/** 单个主机名是否匹配 host/port。哈希名永不匹配；大小写不敏感。 */
function nameMatches(name: string, host: string, port: number): boolean {
  if (name.startsWith('|')) return false;
  const n = name.toLowerCase();
  const h = host.toLowerCase();
  if (port === 22) return n === h || n === `[${h}]:22`;
  return n === `[${h}]:${port}`;
}

/**
 * 查找 host/port 的主机密钥条目。跳过 @revoked / @cert-authority。
 * port=22 匹配裸 host 或 [host]:22；其他端口仅匹配 [host]:port。
 */
export function findHostKeyEntries(entries: KnownHostEntry[], host: string, port: number): KnownHostEntry[] {
  return entries.filter((e) => e.marker === null && e.hosts.some((n) => nameMatches(n, host, port)));
}

/** 生成一行：port=22 -> `host algo blob`；否则 `[host]:port algo blob`。 */
export function formatKnownHostsEntry(e: {
  host: string;
  port: number;
  algorithm: string;
  keyBlob: string;
}): string {
  const name = e.port === 22 ? e.host : `[${e.host}]:${e.port}`;
  return `${name} ${e.algorithm} ${e.keyBlob}`;
}

/**
 * 替换某 host/port 的主机密钥：删除所有匹配条目（裸 host 与 [host]:port 两种形式），
 * 保留注释、空行、@revoked/@cert-authority 行与其他主机；若一行含多个主机名，只移除匹配的那个名字。
 * 追加新行后用 atomicWriteFile 原子替换。文件不存在视为空。
 */
export async function writeKnownHostsEntry(input: {
  file: string;
  host: string;
  port: number;
  algorithm: string;
  keyBlob: string;
  mode: 'replace-host';
}): Promise<void> {
  const { file, host, port, algorithm, keyBlob } = input;
  const existing = (await readTextIfExists(file)) ?? '';
  const lines = existing.split(/\r?\n/);
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();

  const out: string[] = [];
  lines.forEach((line, index) => {
    const entry = parseKnownHostsLine(line, index + 1);
    if (entry === null || entry.marker !== null) {
      out.push(line);
      return;
    }
    const remaining = entry.hosts.filter((name) => !nameMatches(name, host, port));
    if (remaining.length === entry.hosts.length) {
      out.push(line);
      return;
    }
    if (remaining.length === 0) return;
    const rest = line.trim().split(/\s+/).slice(1).join(' ');
    out.push(`${remaining.join(',')} ${rest}`);
  });

  out.push(formatKnownHostsEntry({ host, port, algorithm, keyBlob }));

  await ensureDir(path.dirname(file));
  await atomicWriteFile(file, out.join('\n') + '\n');
}

/**
 * 调用 ssh-keygen -F 查询（可选 -f 指定文件）。exit 0 -> ok 并解析 stdout；
 * 其他情况 ok=false、entries=[]。不抛。raw 为 ssh-keygen 的 stdout。
 * 无法解析的非注释输出行按原样保留为 hosts/算法为空的 raw 条目。
 */
export async function queryUserKnownHosts(input: {
  host: string;
  port: number;
  file?: string;
  sshKeygenPath: string;
  env: NodeJS.ProcessEnv;
}): Promise<{ ok: boolean; entries: KnownHostEntry[]; raw: string }> {
  const target = input.port === 22 ? input.host : `[${input.host}]:${input.port}`;
  const argv = input.file !== undefined ? ['-f', input.file, '-F', target] : ['-F', target];

  let res;
  try {
    res = await spawnCapture({
      file: input.sshKeygenPath,
      argv,
      env: input.env,
      timeoutMs: KEYGEN_TIMEOUT_MS,
      maxOutputBytes: KEYGEN_MAX_OUTPUT_BYTES,
      stdin: 'ignore',
    });
  } catch {
    return { ok: false, entries: [], raw: '' };
  }

  const ok = res.spawnError === undefined && !res.timedOut && res.exitCode === 0;
  if (!ok) return { ok: false, entries: [], raw: res.stdout };

  const entries: KnownHostEntry[] = [];
  res.stdout.split(/\r?\n/).forEach((line, index) => {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) return;
    const entry = parseKnownHostsLine(line, index + 1);
    if (entry !== null) {
      entries.push(entry);
    } else {
      entries.push({ marker: null, hosts: [], algorithm: '', keyBlob: '', raw: line, line: index + 1 });
    }
  });
  return { ok: true, entries, raw: res.stdout };
}
