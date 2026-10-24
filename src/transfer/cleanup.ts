import { promises as fs } from 'node:fs';
import type { TransferDeps } from './deps.js';
import { assertRemoteTempPath, removeRemoteTree } from './stage.js';

export type CleanupKind = 'local' | 'remote';

export interface CleanupHandle {
  kind: CleanupKind;
  path: string;
  /** release() 或 run() 之后为 true。 */
  released: boolean;
}

export interface CleanupFailure {
  kind: CleanupKind;
  path: string;
  code: string;
  message: string;
}

export interface CleanupReport {
  removed: number;
  failures: CleanupFailure[];
  timedOut: boolean;
  durationMs: number;
}

export interface CleanupTrackerInput {
  /** 远端删除需要 deps；未提供时远端项记为 cleanup_unavailable。 */
  deps?: TransferDeps;
  /** 总预算，默认 5000ms。 */
  budgetMs?: number;
  /** 测试注入。 */
  removeLocal?: (path: string) => Promise<void>;
  /** 测试注入。 */
  removeRemote?: (path: string) => Promise<void>;
}

export interface CleanupTracker {
  addLocal(path: string): CleanupHandle;
  addRemote(path: string): CleanupHandle;
  release(handle: CleanupHandle): void;
  pending(): CleanupHandle[];
  readonly failures: readonly CleanupFailure[];
  run(): Promise<CleanupReport>;
}

function errorCode(err: unknown): string {
  if (typeof err === 'object' && err !== null && 'code' in err) {
    const code = (err as { code?: unknown }).code;
    if (typeof code === 'string' && code.length > 0) return code;
  }
  return 'cleanup_failed';
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

async function defaultRemoveRemote(deps: TransferDeps, path: string): Promise<void> {
  const result = await removeRemoteTree(deps, path);
  if (!result.ok) {
    throw new Error(result.error?.message ?? 'remote removal failed');
  }
}

type Timed<T> = { done: true; value: T } | { done: false };

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<Timed<T>> {
  if (ms <= 0) return Promise.resolve({ done: false });
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<Timed<T>>((resolve) => {
    timer = setTimeout(() => resolve({ done: false }), ms);
  });
  return Promise.race([
    promise.then((value): Timed<T> => ({ done: true, value })),
    timeout,
  ]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

/**
 * 清理登记器：local/remote 资源登记、release、run 在总预算内尽力删除。
 * run 只执行一次；失败只记录在 failures，不抛异常。
 */
export function createCleanupTracker(input: CleanupTrackerInput = {}): CleanupTracker {
  const handles: CleanupHandle[] = [];
  const failures: CleanupFailure[] = [];
  const budgetMs = input.budgetMs ?? 5000;
  let reportPromise: Promise<CleanupReport> | undefined;

  const add = (kind: CleanupKind, path: string): CleanupHandle => {
    const handle: CleanupHandle = { kind, path, released: false };
    handles.push(handle);
    return handle;
  };

  const remove = async (handle: CleanupHandle): Promise<void> => {
    if (handle.kind === 'local') {
      if (input.removeLocal !== undefined) return input.removeLocal(handle.path);
      await fs.rm(handle.path, { recursive: true, force: true });
      return;
    }
    if (input.removeRemote !== undefined) return input.removeRemote(handle.path);
    if (input.deps === undefined) {
      throw new Error('remote cleanup requires TransferDeps');
    }
    return defaultRemoveRemote(input.deps, handle.path);
  };

  const tracker: CleanupTracker = {
    addLocal: (path) => add('local', path),
    addRemote: (path) => {
      // 登记期即校验前缀：只有传输层临时路径允许进入远端清理队列。
      assertRemoteTempPath(path);
      return add('remote', path);
    },
    release(handle) {
      handle.released = true;
    },
    pending: () => handles.filter((handle) => !handle.released),
    get failures() {
      return [...failures];
    },
    run() {
      if (reportPromise !== undefined) return reportPromise;
      reportPromise = (async (): Promise<CleanupReport> => {
        const started = Date.now();
        let removed = 0;
        let timedOut = false;
        for (const handle of handles) {
          if (handle.released) continue;
          const remaining = budgetMs - (Date.now() - started);
          if (remaining <= 0) {
            timedOut = true;
            failures.push({
              kind: handle.kind,
              path: handle.path,
              code: 'cleanup_timeout',
              message: 'cleanup budget exhausted',
            });
            handle.released = true;
            continue;
          }
          try {
            const outcome = await withTimeout(remove(handle), remaining);
            if (outcome.done) {
              removed += 1;
            } else {
              timedOut = true;
              failures.push({
                kind: handle.kind,
                path: handle.path,
                code: 'cleanup_timeout',
                message: 'cleanup timed out',
              });
            }
          } catch (err) {
            failures.push({
              kind: handle.kind,
              path: handle.path,
              code: errorCode(err),
              message: errorMessage(err),
            });
          }
          handle.released = true;
        }
        return {
          removed,
          failures: [...failures],
          timedOut,
          durationMs: Date.now() - started,
        };
      })();
      return reportPromise;
    },
  };
  return tracker;
}
