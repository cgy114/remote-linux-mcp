/**
 * P4 会话层的纯类型：不含任何 I/O 或进程逻辑。
 */

/** 会话 id，形如 `sess_<32 hex>`。 */
export type SessionId = string;

/**
 * 控制帧：
 * - `RDY`：远端 bootstrap 完成、read 循环就绪；
 * - `B`：命令 `seq` 开始执行；
 * - `E`：命令 `seq` 结束，退出码 `rc`。
 */
export type Frame =
  | { type: 'RDY' }
  | { type: 'B'; seq: number }
  | { type: 'E'; seq: number; rc: number };

/** 解析器可返回的错误码（错误后解析器进入失败态）。 */
export type FrameParseErrorCode = 'frame_too_long' | 'bad_frame';

/** 一次 push 产出的事件：普通数据或一个控制帧，顺序与输入一致。 */
export type FrameEvent =
  | { type: 'data'; buf: Buffer }
  | { type: 'frame'; frame: Frame };

export interface FrameParseResult {
  events: FrameEvent[];
  error?: FrameParseErrorCode;
}

/** 增量帧解析器；`push` 可接收任意切分的字节片段。 */
export interface FrameParser {
  push(chunk: Buffer | Uint8Array): FrameParseResult;
  /**
   * 输入结束（EOF）时调用：把尚未消费的 carry 作为 data 吐出并清空。
   * 解析器已处于错误态时返回空数组（错误已经上报过）。
   */
  flush(): FrameEvent[];
  /** 已发生的致命解析错误；进入失败态后 push 只返回该错误。 */
  readonly failed: FrameParseErrorCode | undefined;
}

/** 输出文本的编码方式：合法 UTF-8 且无 NUL 时为 utf-8，否则为 base64。 */
export type OutputEncoding = 'utf-8' | 'base64';

/** 输出捕获的最终结果。bytes 为收到的总字节数（含被丢弃的中间部分）。 */
export interface CapturedOutput {
  text: string;
  encoding: OutputEncoding;
  truncated: boolean;
  bytes: number;
}

/** 有界输出捕获：头尾各约 50%，超过上限时保留头尾并标记 truncated。 */
export interface OutputCapture {
  push(chunk: Buffer | Uint8Array): void;
  finish(): CapturedOutput;
  /** 到目前为止收到的总字节数。 */
  readonly bytes: number;
  readonly truncated: boolean;
}

/** 单条命令的执行结果。 */
export type SendOutcome =
  | {
      status: 'ok';
      seq: number;
      rc: number;
      output: CapturedOutput;
      duration_ms: number;
    }
  | {
      status: 'timeout';
      seq: number;
      output: CapturedOutput;
      duration_ms: number;
    }
  | {
      status: 'closed';
      seq: number;
      output: CapturedOutput;
      duration_ms: number;
    }
  | {
      status: 'error';
      seq: number;
      output: CapturedOutput;
      duration_ms: number;
      error: FrameParseErrorCode | 'io';
      message: string;
    };

/** 会话关闭时记录的进程事实。 */
export interface CloseFacts {
  exit_code: number | null;
  signal: string | null;
  /** 是否在宽限期内通过 Q/EOF 优雅退出。 */
  graceful: boolean;
  /** 是否需要本地强杀进程树。 */
  killed: boolean;
  duration_ms: number;
  /**
   * 关闭原因：explicit / idle_timeout / command_timeout / protocol_error /
   * transport_exit / transport_closed / shutdown / trust_revoked /
   * alias_retargeted / stdin_* / SIGINT|SIGTERM|SIGHUP。
   */
  reason: string;
}

/** 会话生命周期状态。 */
export type SessionState = 'starting' | 'ready' | 'busy' | 'closing' | 'closed' | 'failed';

/** session_list 暴露的只读快照。 */
export interface Snapshot {
  id: SessionId;
  /** 目标标识（alias 或 user@host:port，由工具层决定）。 */
  destination: string;
  state: SessionState;
  created_at: number;
  last_activity_at: number;
  idle_timeout_ms: number;
  queue_depth: number;
  commands_run: number;
  output_bytes: number;
  truncated: boolean;
}
