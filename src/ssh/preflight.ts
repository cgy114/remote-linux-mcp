import { promises as fs, constants as fsConstants } from 'node:fs';
import type { EffectiveHost, ErrorFacts, JumpSpec, Logger, MCPPaths, SshSignatures } from '../types.js';
import { resolveToolBinary } from './binary.js';
import { buildChildEnv } from './env.js';
import { spawnCapture } from './runner.js';

const AGENT_TIMEOUT_MS = 5000;
const AGENT_MAX_OUTPUT_BYTES = 64 * 1024;
const KEYGEN_TIMEOUT_MS = 10_000;
const KEYGEN_MAX_OUTPUT_BYTES = 64 * 1024;

// 与 ssh-add -l 输出行匹配：`<bits> SHA256:<b64> <comment> (<type>)`
const FINGERPRINT_LINE_RE = /^\s*\d+\s+(SHA256:\S+)(?:\s|$)/;

/** 认证失败的签名：只置 auth 为真。 */
export function authSignature(): SshSignatures {
  return {
    dns: false,
    tcp: false,
    auth: true,
    hostKeyUnknown: false,
    hostKeyChanged: false,
    sudoPrompt: false,
    connectionTimeout: false,
    other: [],
  };
}

/** 主机密钥未知的签名：只置 hostKeyUnknown 为真。 */
export function hostKeyUnknownSignature(): SshSignatures {
  return {
    dns: false,
    tcp: false,
    auth: false,
    hostKeyUnknown: true,
    hostKeyChanged: false,
    sudoPrompt: false,
    connectionTimeout: false,
    other: [],
  };
}

export type AuthPreflightResult =
  | { ok: true; keySource: 'identity' | 'agent' }
  | { ok: false; fact: ErrorFacts };

export type JumpPreflightResult = { ok: true } | { ok: false; fact: ErrorFacts };

export interface AgentInspection {
  available: boolean;
  fingerprints: string[];
  raw: string;
}

/**
 * 认证前置检查。不抛异常。
 * 有 identityFile：只检查可读性；没有则要求 ssh-agent 中至少有一个指纹。
 */
export async function preflightAuth(input: {
  host: EffectiveHost;
  paths: MCPPaths;
  log: Logger;
}): Promise<AuthPreflightResult> {
  const { host, log } = input;
  try {
    if (host.identityFile !== undefined && host.identityFile !== '') {
      try {
        await fs.access(host.identityFile, fsConstants.R_OK);
      } catch {
        log.debug('identity file is not readable');
        return { ok: false, fact: { phase: 'preflight', signatures: authSignature() } };
      }
      return { ok: true, keySource: 'identity' };
    }

    const sshAddPath = await resolveToolBinary('ssh-add').catch(() => undefined);
    if (sshAddPath !== undefined) {
      const agent = await inspectAgent({ sshAddPath, env: buildChildEnv() });
      if (agent.available && agent.fingerprints.length > 0) {
        return { ok: true, keySource: 'agent' };
      }
    }
    log.debug('no identity file and no usable agent key');
    return {
      ok: false,
      fact: {
        phase: 'preflight',
        signatures: authSignature(),
        stderr: 'no usable identity or agent key',
      },
    };
  } catch {
    return {
      ok: false,
      fact: { phase: 'preflight', signatures: authSignature(), reason: 'internal' },
    };
  }
}

/**
 * 检查每一跳是否已在用户默认 known_hosts 中。任一跳未知即失败。
 * 不抛异常；spawn 失败按未知处理。
 */
export async function preflightJump(input: {
  host: EffectiveHost;
  jumps: JumpSpec[];
  log: Logger;
}): Promise<JumpPreflightResult> {
  const { jumps, log } = input;
  const unknown: JumpPreflightResult = {
    ok: false,
    fact: { phase: 'jump', signatures: hostKeyUnknownSignature(), reason: 'known_hosts_missing' },
  };
  try {
    const env = buildChildEnv();
    for (const jump of jumps) {
      const target =
        jump.port === undefined || jump.port === 22 ? jump.host : `[${jump.host}]:${jump.port}`;
      const known = await isKnownHost(target, env);
      if (!known) {
        log.debug(`jump host not in known_hosts: ${target}`);
        return unknown;
      }
    }
    return { ok: true };
  } catch {
    return unknown;
  }
}

async function isKnownHost(target: string, env: NodeJS.ProcessEnv): Promise<boolean> {
  try {
    const keygenPath = await resolveToolBinary('ssh-keygen');
    const res = await spawnCapture({
      file: keygenPath,
      argv: ['-F', target],
      env,
      timeoutMs: KEYGEN_TIMEOUT_MS,
      maxOutputBytes: KEYGEN_MAX_OUTPUT_BYTES,
      stdin: 'ignore',
    });
    return res.spawnError === undefined && res.exitCode === 0;
  } catch {
    return false;
  }
}

/**
 * 运行 `ssh-add -l` 检查 agent。不抛异常。
 * exit 0 解析指纹；exit 1 且含 "no identities" 或其他错误均视为不可用。
 */
export async function inspectAgent(input: {
  sshAddPath: string;
  env: NodeJS.ProcessEnv;
  timeoutMs?: number;
}): Promise<AgentInspection> {
  try {
    const res = await spawnCapture({
      file: input.sshAddPath,
      argv: ['-l'],
      env: input.env,
      timeoutMs: input.timeoutMs ?? AGENT_TIMEOUT_MS,
      maxOutputBytes: AGENT_MAX_OUTPUT_BYTES,
      stdin: 'ignore',
    });
    if (res.spawnError === undefined && res.exitCode === 0) {
      return {
        available: true,
        fingerprints: parseSshAddOutput(res.stdout).fingerprints,
        raw: res.stdout,
      };
    }
    const raw = `${res.stdout}\n${res.stderr}`.trim();
    // exit 1 + "no identities" 是正常的"无密钥"状态；其他情况同样视为不可用。
    return { available: false, fingerprints: [], raw };
  } catch {
    return { available: false, fingerprints: [], raw: '' };
  }
}

/**
 * 解析 `ssh-add -l` 输出：提取 SHA256 指纹；无指纹的非空行作为 message（取最后一条）。
 */
export function parseSshAddOutput(text: string): { fingerprints: string[]; message?: string } {
  const fingerprints: string[] = [];
  let message: string | undefined;
  for (const line of text.split(/\r?\n/)) {
    if (line.trim() === '') continue;
    const m = FINGERPRINT_LINE_RE.exec(line);
    if (m !== null && m[1] !== undefined) {
      fingerprints.push(m[1]);
    } else {
      message = line.trim();
    }
  }
  const result: { fingerprints: string[]; message?: string } = { fingerprints };
  if (message !== undefined) result.message = message;
  return result;
}
