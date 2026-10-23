/** 每个 key 的 FIFO 并发闸门。 */
export interface HostLimiter {
  /** 等待到可执行槽位；queueMs 为入队到获准的毫秒数，release 幂等。 */
  acquire(key: string): Promise<{ queueMs: number; release: () => void }>;
}

interface Waiter {
  enqueuedAt: number;
  resolve: (lease: { queueMs: number; release: () => void }) => void;
}

interface KeyState {
  active: number;
  waiters: Waiter[];
}

/** 创建每 key 最多 limit 个活跃任务的闸门。 */
export function createHostLimiter(limit: number): HostLimiter {
  if (!Number.isInteger(limit) || limit < 1) {
    throw new Error('host limiter limit must be a positive integer');
  }

  const states = new Map<string, KeyState>();

  const makeLease = (key: string, state: KeyState, enqueuedAt: number) => {
    state.active++;
    let released = false;
    return {
      queueMs: Date.now() - enqueuedAt,
      release: (): void => {
        if (released) return;
        released = true;
        state.active--;
        drain(key, state);
      },
    };
  };

  const drain = (key: string, state: KeyState): void => {
    while (state.active < limit && state.waiters.length > 0) {
      const waiter = state.waiters.shift() as Waiter;
      waiter.resolve(makeLease(key, state, waiter.enqueuedAt));
    }
    if (state.active === 0 && state.waiters.length === 0) {
      states.delete(key);
    }
  };

  return {
    acquire(key: string): Promise<{ queueMs: number; release: () => void }> {
      return new Promise((resolve) => {
        const existing = states.get(key);
        const state: KeyState = existing ?? { active: 0, waiters: [] };
        if (existing === undefined) states.set(key, state);

        if (state.active < limit) {
          resolve(makeLease(key, state, Date.now()));
          return;
        }
        state.waiters.push({ enqueuedAt: Date.now(), resolve });
      });
    },
  };
}

let defaultLimiter: HostLimiter | undefined;

/** 进程单例：每 key 最多 4 个活跃任务。 */
export function getDefaultHostLimiter(): HostLimiter {
  defaultLimiter ??= createHostLimiter(4);
  return defaultLimiter;
}
