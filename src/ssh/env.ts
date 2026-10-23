import os from 'node:os';
import path from 'node:path';

const STRIP_KEYS = ['DISPLAY', 'SSH_ASKPASS', 'GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_SSH_VARIANT'] as const;

function internalError(message: string, code: string): Error {
  const err = new Error(`[Internal] ${message}`) as Error & { code?: string; kind?: string };
  err.code = code;
  err.kind = 'Internal';
  return err;
}

/** 构造子进程环境：复制 base，补齐必要变量，剥离交互式/askpass 相关变量。不修改 base。 */
export function buildChildEnv(input?: {
  base?: NodeJS.ProcessEnv;
  agentSocket?: string;
}): NodeJS.ProcessEnv {
  const base = input?.base ?? process.env;
  const env: NodeJS.ProcessEnv = { ...base };

  const systemRoot = env.SystemRoot && env.SystemRoot.length > 0 ? env.SystemRoot : 'C:\\Windows';
  env.SystemRoot = systemRoot;
  if (!env.ProgramData) env.ProgramData = 'C:\\ProgramData';
  if (!env.USERPROFILE) env.USERPROFILE = os.homedir();
  if (!env.PATH) env.PATH = path.join(systemRoot, 'System32');
  const tmp = os.tmpdir();
  if (!env.TEMP) env.TEMP = tmp;
  if (!env.TMP) env.TMP = tmp;

  for (const key of STRIP_KEYS) delete env[key];

  env.SSH_ASKPASS_REQUIRE = 'never';
  env.LC_ALL = 'C';
  env.LANG = 'C';

  if (input?.agentSocket !== undefined) {
    env.SSH_AUTH_SOCK = input.agentSocket;
  }
  return env;
}

/** 断言环境安全：不允许 askpass/DISPLAY 等交互入口；ProgramData 必须存在。 */
export function assertEnvSafe(env: NodeJS.ProcessEnv): void {
  if ((env.DISPLAY ?? '') !== '' || (env.SSH_ASKPASS ?? '') !== '') {
    throw internalError('unsafe environment: DISPLAY or SSH_ASKPASS is set', 'unsafe_env');
  }
  if (env.SSH_ASKPASS_REQUIRE !== 'never') {
    throw internalError('unsafe environment: SSH_ASKPASS_REQUIRE must be "never"', 'unsafe_env');
  }
  if (!env.ProgramData || env.ProgramData.length === 0) {
    throw internalError('environment missing ProgramData', 'unsafe_env');
  }
}
