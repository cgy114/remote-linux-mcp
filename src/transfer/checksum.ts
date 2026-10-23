import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { renderRemoteShellPath } from '../policy/remote-path.js';

export interface LocalFileHash {
  sha256: string;
  bytes: number;
}

/** 流式计算本地文件 sha256；不把文件读入内存。 */
export async function hashLocalFile(file: string): Promise<LocalFileHash> {
  const hash = createHash('sha256');
  let bytes = 0;
  for await (const chunk of createReadStream(file)) {
    const buf = chunk as Buffer;
    bytes += buf.length;
    hash.update(buf);
  }
  return { sha256: hash.digest('hex'), bytes };
}

/**
 * 远端 sha256 命令片段（参数为已引用的 shell 路径表达式）：
 * 优先 sha256sum，其次 shasum -a 256，最后 openssl dgst -sha256。
 * 都不可用时以 127 退出。
 */
export function remoteHashCommand(renderedPathExpr: string): string {
  const p = renderedPathExpr;
  return [
    `if command -v sha256sum >/dev/null 2>&1; then sha256sum -- ${p} 2>/dev/null;`,
    `elif command -v shasum >/dev/null 2>&1; then shasum -a 256 -- ${p} 2>/dev/null;`,
    `elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 ${p} 2>/dev/null;`,
    'else exit 127; fi',
  ].join(' ');
}

/** 远端 sha256 片段：接收原始远端路径，内部渲染为 "$HOME"/单引号表达式。 */
export function remoteHashSnippet(remotePath: string): string {
  return remoteHashCommand(renderRemoteShellPath(remotePath));
}

/** 从 sha256sum/shasum/openssl 的输出中提取第一个 64 位十六进制串。 */
export function parseSha256(output: string): string | undefined {
  const match = /(?:^|[^0-9a-fA-F])([0-9a-fA-F]{64})(?![0-9a-fA-F])/.exec(output);
  return match?.[1]?.toLowerCase();
}
