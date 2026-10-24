# remote-mcp

把本地 MCP 客户端连接到 SSH 主机的 MCP server：主机检查、一次性命令、sudo、文件传输与持久会话。
默认只允许访问已固定主机密钥的 host，所有命令/传输都会写入脱敏审计。

要求 Node.js >= 24，构建产物在 `dist/`。

```bash
npm install
npm run build
npm test
```

## 作为 MCP server 运行

```bash
remote-mcp --config ~/.remote-mcp/config.yaml
```

stdio 承载 MCP 协议，日志写 stderr（`REMOTE_MCP_LOG_LEVEL=debug|info|warn|error`）。
未指定 `--config` 时读取 `REMOTE_MCP_CONFIG`，否则使用 `~/.remote-mcp/config.yaml`。

## 配置示例

```yaml
version: 1

defaults:
  port: 22
  default_cwd: "~"
  default_host: web1
  timeouts:
    connect_ms: 5000
    command_ms: 15000
    check_ms: 8000
  max_output_bytes: 1048576
  sudo:
    # off | passwordless | password
    mode: passwordless
    # password 模式必填；用 `remote-mcp credential set <ref>` 写入系统凭据库
    credential: sudo.web1
    allow:
      - prefix:systemctl
    deny:
      - prefix:rm

security:
  host_key_policy: pinned
  command_policy:
    # off 保持 P4 及以前的行为（不启用命令策略）
    mode: enforce
    use_default_deny: true
    allow:
      - prefix:ls
      - prefix:cat
    confirm:
      - re: '\b(shutdown|reboot)\b'
    deny:
      - prefix:mkfs
  audit:
    max_bytes: 16777216
    retain_days: 90
    date_rotate: true

hosts:
  web1:
    host: 10.0.0.5
    user: deploy
```

`security.command_policy.mode=off` 与旧配置完全兼容；不写该段时默认 `enforce + use_default_deny`。

## 凭据（sudo 密码）

密码只从 stdin 读取，**不接受 `--password` 参数**，因此不会出现在 argv/进程列表：

```bash
printf '%s\n' "$SUDO_PASSWORD" | remote-mcp credential set sudo.web1
remote-mcp credential set sudo.web1 --stdin < /run/secrets/sudo
remote-mcp credential status sudo.web1     # present / not found（不显示明文）
remote-mcp credential delete sudo.web1
```

凭据存放在操作系统凭据库（Windows Credential Manager / macOS Keychain / Linux Secret Service），
service 名固定为 `remote-mcp`。数据库不可用时工具返回 `sudo_credential_unavailable`。

## ssh_sudo

`ssh_sudo` 只接受 `host`、`command`、`timeout_ms`，没有 `env`/`stdin`/`cwd`/`max_output_bytes`。

- 先求值 `security.command_policy`，再求值 `defaults.sudo.allow/deny`；任一拒绝都在 spawn 前返回 Policy。
- `sudo.mode=passwordless`：`sudo -n -- /bin/bash -lc <inner>`。
- `sudo.mode=password`：`sudo -S -k -p '' -- /bin/bash -lc <inner>`，密码经 stdin 传入后立即清零；
  该模式没有用户 stdin。
- 密码错误、缺少 TTY 或需要密码时返回 `SudoPrompt`。
- 审计记录包含 `tool: "ssh_sudo"`、`sudo_mode`、命令哈希/字节数与运行事实，绝不包含密码。

## 审计

默认写入 `<config dir>/audit.jsonl`：

- 记录先脱敏（provider key、Bearer、`password=`/`token=`/`secret=`/`api_key=`、PEM 私钥、
  URL userinfo、ProxyCommand）再 JSON 序列化；
- 单文件默认 16 MiB，按大小或日期轮转为 `audit-YYYY-MM-DD[.N].jsonl`；
- 归档默认保留 90 天；轮转不会拆分单条记录；
- 写入失败只发 warn，不影响工具结果。

同一进程内所有 append 串行化；跨进程没有锁（见威胁模型）。

## 安全边界

请阅读 [docs/security-threat-model.md](docs/security-threat-model.md)。要点：

- 命令策略是启发式防护，远端 shell 的 eval、别名、profile、base64 解码等可以绕过；
- `read_only` 只约束“是否修改”，不等于保密；
- 审计文件与配置同属当前用户，拥有该用户权限的人可以修改或删除；
- 密码在 Node.js 堆中不可避免地存在短暂副本，只能尽力缩短生命周期；
- 会话关闭不会回收远端后台任务。
