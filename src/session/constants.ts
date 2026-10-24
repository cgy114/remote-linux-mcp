/**
 * P4 持久会话协议的字节常量与容量/超时默认值。
 * 这些值同时被本地解析器与工具层使用，避免两处漂移。
 */

/** Record Separator：帧标记的起始字节。 */
export const RS = 0x1e;
/** Unit Separator：帧标记的结束字节。 */
export const US = 0x1f;

/** nonce 的十六进制长度（16 字节随机数）。 */
export const NONCE_HEX_LENGTH = 32;

/** 未完成帧标记的最大缓冲字节数；超过即 frame_too_long。 */
export const MAX_CARRY_BYTES = 4096;

/** 会话默认空闲超时（15 分钟）。 */
export const DEFAULT_IDLE_TIMEOUT_MS = 900_000;

/** 全局同时存活的会话上限。 */
export const MAX_SESSIONS = 8;
/** 每个 destination 的会话上限。 */
export const MAX_SESSIONS_PER_DESTINATION = 2;
/** 每会话等待执行的命令队列上限。 */
export const MAX_QUEUED_COMMANDS = 8;

/** close 时等待远端优雅退出的宽限期。 */
export const CLOSE_GRACE_MS = 2000;
/** MCP 退出时清理所有会话的总预算。 */
export const SHUTDOWN_BUDGET_MS = 5000;

/** RDY 之前保留的远端诊断输出上限。 */
export const PRE_RDY_DIAGNOSTIC_BYTES = 4096;
/** 本地 ssh stderr 诊断片段上限。 */
export const LOCAL_STDERR_BYTES = 4096;

/** 会话 id 前缀。 */
export const SESSION_ID_PREFIX = 'sess_';
/** 帧标记中的固定魔数前缀。 */
export const MARKER_MAGIC = 'RMCP';
