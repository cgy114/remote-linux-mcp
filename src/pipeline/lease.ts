import { getDefaultHostLimiter, type HostLimiter } from '../ssh/host-limiter.js';

/** 持有主机并发许可期间可读的排队信息。 */
export interface HostLease {
  /** 入队到获准的毫秒数。 */
  queueMs: number;
}

/**
 * 在主机并发闸门下执行 fn；无论 fn 成功或抛错，许可都会被释放。
 * limiter 省略时使用进程单例（每 key 最多 4 个活跃任务）。
 */
export async function withHostLease<T>(
  key: string,
  fn: (lease: HostLease) => Promise<T>,
  limiter: HostLimiter = getDefaultHostLimiter(),
): Promise<T> {
  const permit = await limiter.acquire(key);
  try {
    return await fn({ queueMs: permit.queueMs });
  } finally {
    permit.release();
  }
}
