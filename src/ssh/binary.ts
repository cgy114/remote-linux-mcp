import { promises as fs } from 'node:fs';
import path from 'node:path';

export type ToolName = 'ssh' | 'ssh-keygen' | 'ssh-add' | 'taskkill';

const IS_WIN = process.platform === 'win32';
const cache = new Map<ToolName, string>();

function internalError(name: string): Error {
  const err = new Error(`[Internal] ${name} not found`) as Error & { code?: string; kind?: string };
  err.code = 'binary_missing';
  err.kind = 'Internal';
  return err;
}

function systemRoot(): string {
  return process.env.SystemRoot ?? 'C:\\Windows';
}

function systemCandidate(name: ToolName): string | undefined {
  const root = systemRoot();
  if (name === 'taskkill') return path.join(root, 'System32', 'taskkill.exe');
  return path.join(root, 'System32', 'OpenSSH', `${name}.exe`);
}

async function isExecutable(file: string): Promise<boolean> {
  try {
    await fs.access(file, IS_WIN ? fs.constants.F_OK : fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

async function scanPath(name: ToolName): Promise<string | undefined> {
  const dirs = (process.env.PATH ?? '').split(path.delimiter).filter((d) => d.length > 0);
  const base = IS_WIN ? `${name}.exe` : name;
  for (const dir of dirs) {
    const candidate = path.join(dir, base);
    if (await isExecutable(candidate)) return path.resolve(candidate);
  }
  return undefined;
}

/** 解析工具的绝对路径；按 name 缓存；不 spawn 子进程。 */
export async function resolveToolBinary(name: ToolName): Promise<string> {
  const cached = cache.get(name);
  if (cached !== undefined) return cached;

  if (IS_WIN) {
    const sys = systemCandidate(name);
    if (sys !== undefined && (await isExecutable(sys))) {
      cache.set(name, sys);
      return sys;
    }
  }

  const found = await scanPath(name);
  if (found === undefined) throw internalError(name);
  cache.set(name, found);
  return found;
}

/** 解析 ssh 路径；位于 System32\OpenSSH 下视为 system，否则 path。 */
export async function resolveSshBinary(): Promise<{ path: string; source: 'path' | 'system' }> {
  const p = await resolveToolBinary('ssh');
  const sysDir = path.join(systemRoot(), 'System32', 'OpenSSH').toLowerCase();
  const source = IS_WIN && path.dirname(p).toLowerCase() === sysDir ? 'system' : 'path';
  return { path: p, source };
}
