import { describe, expect, it, vi } from 'vitest';

const { flushMock } = vi.hoisted(() => ({ flushMock: vi.fn() }));

// 只替换审计 sink 的 flush，其余模块保持真实实现。
vi.mock('../../src/audit/sink.js', () => ({ flushAuditSinks: flushMock }));

import { flushAuditBeforeExit, shutdown } from '../../src/lifecycle.js';
import type { Logger } from '../../src/types.js';

function makeLogger(): Logger & { warn: ReturnType<typeof vi.fn> } {
  const logger: Logger = {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    child: () => logger,
  };
  return logger as Logger & { warn: ReturnType<typeof vi.fn> };
}

describe('flushAuditBeforeExit', () => {
  it('waits for the audit queue to drain', async () => {
    flushMock.mockResolvedValueOnce(undefined);
    const log = makeLogger();
    await expect(flushAuditBeforeExit(log, 50)).resolves.toBeUndefined();
    expect(flushMock).toHaveBeenCalledTimes(1);
    expect(log.warn).not.toHaveBeenCalled();
  });

  it('warns and resolves when the audit flush rejects', async () => {
    flushMock.mockRejectedValueOnce(new Error('boom'));
    const log = makeLogger();
    await expect(flushAuditBeforeExit(log, 50)).resolves.toBeUndefined();
    expect(log.warn).toHaveBeenCalledWith(
      { err: expect.objectContaining({ message: 'boom' }) },
      'audit flush failed',
    );
  });

  it('warns and resolves when the audit flush exceeds its budget', async () => {
    flushMock.mockReturnValueOnce(new Promise<void>(() => undefined));
    const log = makeLogger();
    await expect(flushAuditBeforeExit(log, 10)).resolves.toBeUndefined();
    expect(log.warn).toHaveBeenCalledWith(
      { timeoutMs: 10 },
      'audit flush exceeded shutdown budget',
    );
  });
});

describe('shutdown', () => {
  it('flushes audit sinks before resolving', async () => {
    const log = makeLogger();
    flushMock.mockResolvedValue(undefined);
    await shutdown({ reason: 'test', log, graceMs: 20, auditFlushMs: 20 });
    expect(flushMock).toHaveBeenCalled();
  });
});
