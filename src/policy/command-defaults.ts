/**
 * 内置危险命令规则表。
 *
 * 规则只描述“危险命令”）——不负责执行或提示文案排版。
 * `spec` 与配置语法一致：`re:` 为正则（不加锚点），`prefix:` / 裸字符串为前缀。
 * `reason` 为面向用户的中文说明。
 */

export interface BuiltinRuleDef {
  id: string;
  spec: string;
  reason: string;
  /** 不可安全解释的命令（解释器 / 包装器 / 提权程序）。 */
  hard?: boolean;
  /** 高破坏性命令。 */
  dangerous?: boolean;
}

/**
 * 片段起始位置：行首、分隔符之后，并允许前置环境赋值。
 * 换行保留在骨架中，因此也要作为分隔符。
 */
const SEG = String.raw`(?:^|[;&|\n]\s*)(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&|\n]*\s+)*`;

/** 生成以片段起始为锚点的正则规则。 */
const re = (body: string): string => `re:${SEG}${body}`;

/** 前置一个（可带转义/引号）反斜杠的 rm 标志。 */
const RM_RF =
  String.raw`rm\s+(?=[^;&|\n]*-{1,2}[A-Za-z]*r)(?=[^;&|\n]*-{1,2}[A-Za-z]*f)[^;&|\n]*\s+`;

export const BUILTIN_RULE_DEFS: readonly BuiltinRuleDef[] = [
  {
    id: 'rm-rf-root',
    spec: re(String.raw`${RM_RF}\/(?:\s|$)`),
    reason: '递归强制删除根目录 /',
    dangerous: true,
  },
  {
    id: 'rm-rf-home',
    spec: re(String.raw`${RM_RF}(?:~|\$HOME|\$\{HOME\})(?:\/|\s|$)`),
    reason: '递归强制删除用户主目录',
    dangerous: true,
  },
  { id: 'mkfs', spec: re(String.raw`mkfs(?:\.[A-Za-z0-9]+)?\s`), reason: '格式化文件系统', dangerous: true },
  { id: 'mke2fs', spec: 'prefix:mke2fs', reason: '创建 ext 文件系统', dangerous: true },
  { id: 'wipefs', spec: 'prefix:wipefs', reason: '擦除文件系统签名', dangerous: true },
  { id: 'fdisk', spec: 'prefix:fdisk', reason: '修改磁盘分区表', dangerous: true },
  { id: 'parted', spec: 'prefix:parted', reason: '修改磁盘分区表', dangerous: true },
  { id: 'sgdisk', spec: 'prefix:sgdisk', reason: '修改 GPT 分区表', dangerous: true },
  {
    id: 'dd-to-device',
    spec: re(String.raw`dd\s+[^;&|\n]*\bof=\s*\/dev\/`),
    reason: '向块设备写入数据（可能覆盖磁盘）',
    dangerous: true,
  },
  { id: 'shutdown', spec: 'prefix:shutdown', reason: '关闭主机', dangerous: true },
  { id: 'reboot', spec: 'prefix:reboot', reason: '重启主机', dangerous: true },
  { id: 'poweroff', spec: 'prefix:poweroff', reason: '关闭主机电源', dangerous: true },
  { id: 'halt', spec: 'prefix:halt', reason: '停止主机', dangerous: true },
  { id: 'init-0', spec: re(String.raw`init\s+0(?:\s|$)`), reason: '切换到关机运行级别', dangerous: true },
  {
    id: 'kill-all',
    spec: re(String.raw`kill\s+-9\s+-1(?:\s|$)`),
    reason: '向所有进程发送 SIGKILL',
    dangerous: true,
  },
  {
    id: 'fork-bomb',
    spec: re(String.raw`:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`),
    reason: 'fork 炸弹会耗尽进程资源',
    dangerous: true,
  },
  {
    id: 'curl-pipe-shell',
    spec: re(String.raw`curl\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|da|k|z)?sh\b`),
    reason: '把下载内容直接交给 shell 执行',
    dangerous: true,
  },
  {
    id: 'wget-pipe-shell',
    spec: re(String.raw`wget\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|da|k|z)?sh\b`),
    reason: '把下载内容直接交给 shell 执行',
    dangerous: true,
  },
  {
    id: 'base64-pipe-shell',
    spec: re(String.raw`base64\s+(?:-d|--decode)\b[^|\n]*\|[^|\n]*\b(?:ba|da|k|z)?sh\b`),
    reason: '解码后直接交给 shell 执行',
    dangerous: true,
  },
  {
    id: 'eval-remote',
    spec: re(String.raw`eval\b[^;&|\n]*\$\(\s*(?:curl|wget)\b`),
    reason: '执行远程下载的内容',
    dangerous: true,
  },
  {
    id: 'authorized-keys-write',
    spec: re(
      String.raw`[^\n]*(?:>>?|\btee\b|\bcp\b|\bmv\b|\binstall\b|\bdd\b)[^\n]*(?:\.ssh\/)?authorized_keys\b`,
    ),
    reason: '写入 SSH 授权密钥（可能被用于持久化访问）',
    dangerous: true,
  },
  {
    id: 'sudoers-write',
    spec: re(
      String.raw`[^\n]*(?:>>?|\btee\b|\bcp\b|\bmv\b|\binstall\b|\bchmod\b|\bchown\b|\bvisudo\b|\bsed\s+-i\b)[^\n]*\/etc\/sudoers\b`,
    ),
    reason: '修改 sudoers（提权配置）',
    dangerous: true,
  },
  {
    id: 'passwd-shadow-write',
    spec: re(
      String.raw`[^\n]*(?:>>?|\btee\b|\bcp\b|\bmv\b|\binstall\b|\bchmod\b|\bchown\b|\bsed\s+-i\b|\bchpasswd\b)[^\n]*\/etc\/(?:passwd|shadow|gshadow)\b`,
    ),
    reason: '修改系统账户数据库',
    dangerous: true,
  },
  {
    id: 'chmod-777-root',
    spec: re(String.raw`chmod\s+(?:--?[A-Za-z]+\s+)*777\s+\/(?:\s|$)`),
    reason: '把根目录权限改为 777',
    dangerous: true,
  },
  {
    id: 'chown-root-recursive',
    spec: re(String.raw`chown\s+(?:--?[A-Za-z]+\s+)*\S+\s+\/(?:\s|$)`),
    reason: '递归修改根目录归属',
    dangerous: true,
  },
  {
    id: 'iptables-flush',
    spec: re(String.raw`iptables\s+(?:--?[A-Za-z]+\s+)*-F(?:\s|$)`),
    reason: '清空防火墙规则',
    dangerous: true,
  },
  {
    id: 'nft-flush-ruleset',
    spec: re(String.raw`nft\s+flush\s+ruleset\b`),
    reason: '清空 nftables 规则集',
    dangerous: true,
  },
  { id: 'ufw-disable', spec: re(String.raw`ufw\s+disable\b`), reason: '关闭防火墙', dangerous: true },
  {
    id: 'setenforce-0',
    spec: re(String.raw`setenforce\s+0(?:\s|$)`),
    reason: '关闭 SELinux 强制模式',
    dangerous: true,
  },
  {
    id: 'crontab-remove',
    spec: re(String.raw`crontab\s+(?:-r|--remove)\b`),
    reason: '删除当前用户的全部定时任务',
    dangerous: true,
  },
  { id: 'mv-root', spec: re(String.raw`mv\s+\/(?:\s|$)`), reason: '移动根目录', dangerous: true },
  {
    id: 'umount-root',
    spec: re(String.raw`umount\s+(?:--?[A-Za-z]+\s+)*\/(?:\s|$)`),
    reason: '卸载根文件系统',
    dangerous: true,
  },
  {
    id: 'swapoff-all',
    spec: re(String.raw`swapoff\s+(?:-a|--all)\b`),
    reason: '关闭所有交换分区',
    dangerous: true,
  },
  {
    id: 'docker-privileged',
    spec: re(String.raw`docker\s+(?:run|create)\b[^\n]*--privileged\b`),
    reason: '启动特权容器（可逃逸到宿主机）',
    dangerous: true,
  },
  {
    id: 'usermod-sudo-group',
    spec: re(String.raw`usermod\b[^\n]*(?:-[aA]G|--groups)\s+[^\n]*\bsudo\b`),
    reason: '把用户加入 sudo 组',
    dangerous: true,
  },
  { id: 'ssh-copy-id', spec: 'prefix:ssh-copy-id', reason: '安装 SSH 公钥到远端', dangerous: true },

  // ---- hard：解释器 / 包装器 / 提权程序 ----
  { id: 'hard-sudo', spec: 'prefix:sudo', reason: '不允许直接调用 sudo', hard: true },
  { id: 'hard-su', spec: 'prefix:su', reason: '不允许直接调用 su', hard: true },
  { id: 'hard-doas', spec: 'prefix:doas', reason: '不允许直接调用 doas', hard: true },
  { id: 'hard-pkexec', spec: 'prefix:pkexec', reason: '不允许直接调用 pkexec', hard: true },
  { id: 'hard-bash', spec: 'prefix:bash', reason: '不允许调用 shell 解释器', hard: true },
  { id: 'hard-sh', spec: 'prefix:sh', reason: '不允许调用 shell 解释器', hard: true },
  { id: 'hard-dash', spec: 'prefix:dash', reason: '不允许调用 shell 解释器', hard: true },
  { id: 'hard-zsh', spec: 'prefix:zsh', reason: '不允许调用 shell 解释器', hard: true },
  { id: 'hard-ksh', spec: 'prefix:ksh', reason: '不允许调用 shell 解释器', hard: true },
  { id: 'hard-fish', spec: 'prefix:fish', reason: '不允许调用 shell 解释器', hard: true },
  { id: 'hard-csh', spec: 'prefix:csh', reason: '不允许调用 shell 解释器', hard: true },
  { id: 'hard-tcsh', spec: 'prefix:tcsh', reason: '不允许调用 shell 解释器', hard: true },
  { id: 'hard-python', spec: 'prefix:python', reason: '不允许调用通用解释器', hard: true },
  { id: 'hard-python2', spec: 'prefix:python2', reason: '不允许调用通用解释器', hard: true },
  { id: 'hard-python3', spec: 'prefix:python3', reason: '不允许调用通用解释器', hard: true },
  { id: 'hard-perl', spec: 'prefix:perl', reason: '不允许调用通用解释器', hard: true },
  { id: 'hard-ruby', spec: 'prefix:ruby', reason: '不允许调用通用解释器', hard: true },
  { id: 'hard-node', spec: 'prefix:node', reason: '不允许调用通用解释器', hard: true },
  { id: 'hard-nodejs', spec: 'prefix:nodejs', reason: '不允许调用通用解释器', hard: true },
  { id: 'hard-deno', spec: 'prefix:deno', reason: '不允许调用通用解释器', hard: true },
  { id: 'hard-bun', spec: 'prefix:bun', reason: '不允许调用通用解释器', hard: true },
  { id: 'hard-awk', spec: 'prefix:awk', reason: '不允许调用 awk（可执行外部命令）', hard: true },
  { id: 'hard-gawk', spec: 'prefix:gawk', reason: '不允许调用 awk（可执行外部命令）', hard: true },
  { id: 'hard-mawk', spec: 'prefix:mawk', reason: '不允许调用 awk（可执行外部命令）', hard: true },
  { id: 'hard-env', spec: 'prefix:env', reason: '不允许通过 env 包装执行命令', hard: true },
  { id: 'hard-xargs', spec: 'prefix:xargs', reason: '不允许通过 xargs 包装执行命令', hard: true },
  {
    id: 'hard-find-exec',
    spec: re(String.raw`find\b[^\n]*-exec(?:dir)?\b`),
    reason: '不允许通过 find -exec 执行命令',
    hard: true,
  },
  {
    id: 'hard-tar-to-command',
    spec: re(String.raw`tar\b[^\n]*--to-command\b`),
    reason: '不允许通过 tar --to-command 执行命令',
    hard: true,
  },
  { id: 'hard-rsync', spec: 'prefix:rsync', reason: '不允许调用 rsync（可作为命令通道）', hard: true },
  { id: 'hard-scp', spec: 'prefix:scp', reason: '不允许调用 scp（可作为命令通道）', hard: true },
  { id: 'hard-ssh', spec: 'prefix:ssh', reason: '不允许调用 ssh（可作为命令通道）', hard: true },
  { id: 'hard-nc', spec: 'prefix:nc', reason: '不允许调用 nc/netcat（可作为命令通道）', hard: true },
  { id: 'hard-netcat', spec: 'prefix:netcat', reason: '不允许调用 nc/netcat（可作为命令通道）', hard: true },
  { id: 'hard-ncat', spec: 'prefix:ncat', reason: '不允许调用 nc/netcat（可作为命令通道）', hard: true },
  { id: 'hard-socat', spec: 'prefix:socat', reason: '不允许调用 socat（可作为命令通道）', hard: true },
  { id: 'hard-curl', spec: 'prefix:curl', reason: '不允许调用 curl（可下载并执行内容）', hard: true },
  { id: 'hard-wget', spec: 'prefix:wget', reason: '不允许调用 wget（可下载并执行内容）', hard: true },
  { id: 'hard-eval', spec: 'prefix:eval', reason: '不允许使用 eval', hard: true },
  { id: 'hard-exec', spec: 'prefix:exec', reason: '不允许使用 exec', hard: true },
  { id: 'hard-source', spec: 'prefix:source', reason: '不允许使用 source', hard: true },
  { id: 'hard-dot', spec: 'prefix:.', reason: '不允许使用 . 加载脚本', hard: true },
  { id: 'hard-busybox', spec: 'prefix:busybox', reason: '不允许通过 busybox 调用任意 applet', hard: true },
];

const REASONS = new Map(BUILTIN_RULE_DEFS.map((def) => [def.id, def.reason]));

/** 内置规则的 id -> 中文 reason。 */
export function builtinReason(id: string): string | undefined {
  return REASONS.get(id);
}
