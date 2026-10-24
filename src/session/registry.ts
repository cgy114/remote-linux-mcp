import { UsageError } from '../errors/classes.js';
import { withTimeout } from '../lifecycle.js';
import { MAX_QUEUED_COMMANDS, MAX_SESSIONS, MAX_SESSIONS_PER_DESTINATION } from './constants.js';
import type { Session } from './session.js';
import type { SessionId } from './types.js';

/**
 * 一次「正在启动」的会话占位。prepare 阶段获取，execute 成功后 commit，
 * 失败（或任何异常）必须 abort，否则容量会被永久占用。
 */
export interface SessionReservation {
  readonly destination: string;
  readonly active: boolean;
  commit(session: Session): void;
  abort(): void;
}

export interface SessionRegistry {
  /** 预占一个名额；超过全局/单目标上限时抛 UsageError(too_many_sessions)。 */
  beginStart(destination: string): SessionReservation;
  commitStart(reservation: SessionReservation, session: Session): void;
  abortStart(reservation: SessionReservation): void;
  get(id: SessionId): Session | undefined;
  list(): Session[];
  delete(id: SessionId): boolean;
  /** 并发关闭全部会话，最多等待 budgetMs；永不 reject。 */
  closeAll(reason: string, budgetMs: number): Promise<void>;
  readonly maxGlobal: number;
  readonly maxPerDest: number;
  readonly maxQueue: number;
  readonly size: number;
}

export interface SessionRegistryOptions {
  maxGlobal?: number;
  maxPerDest?: number;
  maxQueue?: number;
}

function tooMany(message: string): UsageError {
  return new UsageError(message, { code: 'too_many_sessions' });
}

interface ReservationState {
  destination: string;
  active: boolean;
}

/** 创建进程内会话登记簿（容量按目标与全局双重限制）。 */
export function createSessionRegistry(options: SessionRegistryOptions = {}): SessionRegistry {
  const maxGlobal = options.maxGlobal ?? MAX_SESSIONS;
  const maxPerDest = options.maxPerDest ?? MAX_SESSIONS_PER_DESTINATION;
  const maxQueue = options.maxQueue ?? MAX_QUEUED_COMMANDS;

  const sessions = new Map<SessionId, Session>();
  const reservations = new Map<SessionReservation, ReservationState>();

  const countFor = (destination: string): number => {
    let count = 0;
    for (const session of sessions.values()) {
      if (session.destination === destination) count += 1;
    }
    for (const state of reservations.values()) {
      if (state.destination === destination) count += 1;
    }
    return count;
  };

  const release = (reservation: SessionReservation): ReservationState | undefined => {
    const state = reservations.get(reservation);
    if (state === undefined) return undefined;
    reservations.delete(reservation);
    state.active = false;
    return state;
  };

  const registry: SessionRegistry = {
    maxGlobal,
    maxPerDest,
    maxQueue,
    get size(): number {
      return sessions.size + reservations.size;
    },

    beginStart(destination: string): SessionReservation {
      if (sessions.size + reservations.size >= maxGlobal) {
        throw tooMany(`at most ${maxGlobal} sessions may exist at once`);
      }
      if (countFor(destination) >= maxPerDest) {
        throw tooMany(`at most ${maxPerDest} sessions may target ${destination}`);
      }
      const state: ReservationState = { destination, active: true };
      const reservation: SessionReservation = {
        destination,
        get active(): boolean {
          return state.active;
        },
        commit(session: Session): void {
          registry.commitStart(reservation, session);
        },
        abort(): void {
          registry.abortStart(reservation);
        },
      };
      reservations.set(reservation, state);
      return reservation;
    },

    commitStart(reservation: SessionReservation, session: Session): void {
      const state = release(reservation);
      if (state === undefined) throw new Error('session reservation is not active');
      if (sessions.has(session.id)) {
        throw new UsageError(`session ${session.id} already exists`, { code: 'session_exists' });
      }
      sessions.set(session.id, session);
    },

    abortStart(reservation: SessionReservation): void {
      release(reservation);
    },

    get(id: SessionId): Session | undefined {
      return sessions.get(id);
    },

    list(): Session[] {
      return [...sessions.values()];
    },

    delete(id: SessionId): boolean {
      return sessions.delete(id);
    },

    async closeAll(reason: string, budgetMs: number): Promise<void> {
      const closing = [...sessions.values()];
      sessions.clear();
      reservations.clear();
      if (closing.length === 0) return;
      try {
        const all = Promise.all(
          closing.map(async (session) => {
            try {
              await session.close(reason);
            } catch {
              // close 本身约定不 reject；这里再兜底一次。
            }
          }),
        );
        await withTimeout(all, Math.max(0, budgetMs));
      } catch {
        // 永不 reject
      }
    },
  };

  return registry;
}

let singleton: SessionRegistry | undefined;

/** 进程单例：全局 8 / 每目标 2 / 队列 8。 */
export function getSessionRegistry(): SessionRegistry {
  singleton ??= createSessionRegistry();
  return singleton;
}

/** 测试用：替换或清除单例。 */
export function resetSessionRegistry(registry?: SessionRegistry): void {
  singleton = registry;
}
