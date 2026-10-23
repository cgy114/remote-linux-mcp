const inflight = new Map<string, Promise<unknown>>();

/**
 * 单飞：同一 key 在途时复用同一个 Promise；settle（成功或失败）后删除；不缓存结果。
 */
export function singleFlight<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const existing = inflight.get(key);
  if (existing !== undefined) {
    return existing as Promise<T>;
  }
  const p: Promise<T> = (async () => fn())().finally(() => {
    if (inflight.get(key) === p) {
      inflight.delete(key);
    }
  });
  inflight.set(key, p);
  return p;
}
