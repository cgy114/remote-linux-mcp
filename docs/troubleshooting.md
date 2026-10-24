# 故障排查

本文按症状组织。先做三条只读检查，通常能定位大部分问题：

```powershell
# 1) MCP 注册与连接状态
claude mcp list

# 2) 配置、alias、信任状态（需要先构建 dist）
node scripts/check-config.mjs --json --require-trusted orangepi

# 3) 远端前置条件（在 Ubuntu 主机上运行）
bash scripts/ubuntu-preflight.sh --json
```

约定：

- 配置目录默认 `~/.remote-mcp`（Windows 为 `%USERPROFILE%\.remote-mcp`），其中
  `config.yaml`、`known_hosts`、`trusted.json`、`audit.jsonl` 同目录。
- 工具错误统一是 `{ error: { kind, code, message, hint, retryable, details } }`。
  排查时优先看 `kind` 与 `code`，`details` 里常有策略的 `ruleId`。
- 日志写 stderr，`REMOTE_MCP_LOG_LEVEL=debug|info|warn|error` 控制级别。
- 下文的 `remote-mcp ...` 指已安装的 CLI；未全局安装时用
  `node .\dist\cli.js ...` 替代同一子命令。
- 本文只给命令和判断方法；所有修复都需要你确认后再执行。

## 1. MCP 未连接

`claude mcp list` 中 `remote-mcp` 应显示 `Connected`。未注册或连接失败时：

1. 确认构建产物存在：`Test-Path .\dist\cli.js`；不存在就运行 `npm run build`。
2. 确认注册命令是绝对路径的 `node.exe`、`dist/cli.js` 和 `--config`：
   重新运行 `install.ps1`（默认会更新注册），然后重启 Claude Code。
3. 手动检查配置：`node scripts/check-config.mjs --config "$HOME\.remote-mcp\config.yaml"`。
   `exit 2` 通常表示 `dist` 未构建；`exit 3` 表示配置/信任文件错误。
4. 查看安装状态：`%LOCALAPPDATA%\remote-mcp\install.json`。
   若仓库被移动过，其中的路径会过期，重跑 `install.ps1` 即可刷新。
5. 用 debug 日志直接启动一次 server（会等待 stdio 输入，Ctrl+C 退出）：

   ```powershell
   $env:REMOTE_MCP_LOG_LEVEL = 'debug'
   node .\dist\cli.js --config "$HOME\.remote-mcp\config.yaml"
   ```

常见原因：

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `claude mcp list` 没有条目 | 未注册或注册被移除 | 运行 `install.ps1`（可加 `-SkipBuild`） |
| 显示 `Failed` / 立即退出 | `dist/cli.js` 缺失、配置 YAML 非法、Node 路径过期 | 重建、`check-config`、重新安装 |
| 安装时 Connected 检查失败 | `claude` CLI 不可用或需要重启客户端 | 确认 `claude mcp list` 可运行，重启 Claude Code |
| 工具调用返回 `Internal` / `internal_error` | 本地无法启动 `ssh` | 确认 `ssh.exe` 在 PATH；见日志 |
| 工具调用返回 `Policy` / `config_*` | 配置 schema 或路径问题 | 运行 `check-config` |

安装/卸载的参数与退出码见 [README](../README.md#installps1-参数)、
[README](../README.md#退出码)。

## 2. Host key、trust 与 rotate

默认策略是 `pinned`：第一次连接前必须固定主机密钥，否则返回
`kind=HostKey`、`code=host_key`。

首次信任：

```powershell
node .\dist\cli.js trust web1
# 非交互（CI/脚本）：先独立核对指纹，再传入
node .\dist\cli.js trust web1 --fingerprint SHA256:xxxxxxxx
```

在远端独立获取指纹（不要只信客户端第一次看到的值）：

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
# 或
ssh-keyscan -t ed25519 host.example.com | ssh-keygen -lf -
```

主机重装、IP 复用或算法变化会导致指纹不一致。此时：

1. 先通过带外渠道确认新指纹；
2. 再允许替换固定值：

   ```powershell
   node .\dist\cli.js trust web1 --rotate --fingerprint SHA256:新指纹
   ```

不要在不核对的情况下使用 `--rotate`，否则固定主机密钥失去意义。

其他检查：

- `trusted.json` 损坏时 `check-config` 返回 `exit 3`；`known_hosts` 损坏通常会在
  连接阶段表现为 `HostKey` 错误。不要手工拼接 JSON/known_hosts；重新执行 `trust`
  是受支持的修复路径。
- `host_list` 的 `pinnedFingerprint` 可用来与远端指纹对照。
- E2E 测试的期望指纹由 `REMOTE_MCP_E2E_FINGERPRINT` 覆盖，默认值见
  `test/integration/host-check-real.test.ts`。

## 3. 认证与 agent

`kind=Auth`、`code=auth_failed` 表示 SSH 认证失败。按顺序检查：

1. **私钥路径与权限**：`identity_file` 指向的私钥必须存在；Windows 上
   OpenSSH 对私钥 ACL 较严格，Linux 上应为 `600`、`~/.ssh` 为 `700`。
2. **agent**：`ssh-add -l` 应列出对应密钥。Windows 使用 OpenSSH
   Authentication Agent 服务；Git Bash 的 agent 与 Windows 服务不是同一个。
   `SSH_AUTH_SOCK` 指错时，先 `ssh-add -l` 确认。
3. **远端 authorized_keys**：权限 `600`、所有者为目标用户；
   `~/.ssh` 为 `700`；home 不能被组或其他用户写（sshd StrictModes 会拒绝）。
   预检脚本的 `ssh-dir` / `authorized-keys` / `home-perm` 项会直接标出。
4. **用户名/端口**：配置中的 `user` 与 `port` 必须与远端一致；`host` 是 IP
   或可解析域名。
5. **ProxyJump**：多跳链路上每一跳都要能认证；任一跳失败都会表现为
   `auth_failed` 或 `tcp_failed`。
6. 需要更详细的过程时，用相同参数手工运行：

   ```powershell
   ssh -vv -p 22 -i $HOME\.ssh\id_ed25519 orangepi@host.example.com true
   ```

`remote-mcp` 会剥离 `SSH_ASKPASS`、`DISPLAY` 等交互入口，并设置
`SSH_ASKPASS_REQUIRE=never`，因此不会弹出密码框；需要密码的登录方式应改用密钥
或 agent。

## 4. sudo

`ssh_sudo` 的 `sudo.mode` 有三种：

| mode | 行为 | 前提 |
| --- | --- | --- |
| `off` | 拒绝 `ssh_sudo`，`code=sudo_disabled` | 无 |
| `passwordless` | `LC_ALL=C sudo -n -- bash -lc ...` | 远端有 NOPASSWD 规则 |
| `password` | `LC_ALL=C sudo -S -k -p '' ...`，密码经 stdin 传入 | 凭据库中有对应 ref |

常见错误：

| code | 含义 | 处理 |
| --- | --- | --- |
| `sudo_disabled` | 配置为 `off` | 改为 `passwordless` 或 `password` |
| `sudo_credential_missing` | 未配置凭据或 ref 不存在 | `remote-mcp credential set sudo.web1` |
| `sudo_credential_invalid` | 凭据为空/格式非法 | 重新写入一行密码（不带换行以外的内容） |
| `sudo_credential_timeout` | 读取系统凭据库超时 | 检查系统凭据库/密钥环是否可用 |
| `sudo_credential_unavailable` | 系统凭据库不可用 | Windows 凭据管理器/Linux Secret Service 未运行 |
| `sudo_prompt`（`kind=SudoPrompt`） | sudo 仍要求密码或 TTY | 配置 NOPASSWD，或改用 `password` 模式 |

排查命令：

```bash
# 远端是否允许无密码 sudo（只读，无副作用）
sudo -n true && echo NOPASSWD_OK || echo NEEDS_PASSWORD
```

```powershell
remote-mcp credential status sudo.web1   # present / not found，不显示明文
$env:SUDO_PASSWORD | remote-mcp credential set sudo.web1 --stdin
```

注意：

- `ssh_sudo` 不接受 `env`、`stdin`、`cwd`、`max_output_bytes`；密码只走内部 stdin。
- 需要 TTY 的 sudoers 配置（`requiretty`）必须关闭，否则只能得到 `SudoPrompt`。
- 运行时固定 `LC_ALL=C`，让 sudo 的英文提示可被识别；不要在 sudoers 中覆盖它。
- `defaults.sudo.allow/deny` 在 spawn 前求值；`ssh_exec`/`session_send` 中直接调用
  `sudo` 会被内置 `hard-sudo` 规则拒绝，应使用 `ssh_sudo` 工具。
- 审计只记录模式、命令哈希与运行事实，不记录密码。

## 5. 编码

- 工具输出按 UTF-8 处理；远端命令可能继承客户端固定的 `LC_ALL=C`，因此
  `date`、`sort` 等命令的输出可能是英文/字节序。需要 UTF-8 时显式传环境变量：

  ```json
  { "host": "web1", "command": "printf '%s' \"$LANG\"", "env": { "LANG": "C.UTF-8" } }
  ```

- 在 Windows 控制台直接查看中文/emoji 乱码，通常是显示代码页问题，不是数据损坏。
  PowerShell 中可先 `chcp 65001`，或把结果写入 UTF-8 文件再查看。
- YAML 中的正则使用双引号时，反斜杠要写成 `\\`，否则 `\b` 会被解释为退格。
- 远端文件名含非 ASCII 时，确认远端 locale 为 UTF-8（预检的 `locale` 项）；
  传输本身按字节处理，不受 locale 影响。
- 配置文件请保存为 UTF-8（建议无 BOM）；不要用会改变编码的编辑器保存。

## 6. 防火墙与网络

`kind=TCP`、`code=tcp_failed` 表示 TCP 连接失败；`kind=DNS` 表示域名解析失败。

- 先确认端口正确：配置的 `port` 与远端 `sshd` 监听端口一致。预检的
  `sshd-port` 会打印有效端口。
- 在远端确认 sshd 在监听：`ss -ltn | grep :22`。
- 本机到远端的连通性：

  ```powershell
  Test-NetConnection host.example.com -Port 22
  ssh -vv -p 22 user@host.example.com true
  ```

- ufw：`sudo ufw status`；放行示例 `sudo ufw allow 22/tcp`（自行确认后再执行）。
- firewalld：`sudo firewall-cmd --list-ports`；nftables/iptables：确认 INPUT 链允许端口。
- 云主机还需检查安全组/网络 ACL；Tailscale/WireGuard 场景确认对端在线且路由可达。
- 预检脚本在无 root 时会把防火墙状态标为 `SKIP`，不会修改规则。
- `host_check` 的 `check_ms` 默认 8000；Tailscale/VPN 首次握手较慢时可能超时。
  该错误 `retryable=true`，重试一次通常即可；持续超时再检查链路质量或调大超时。

## 7. 命令策略误拦

策略错误是 `kind=Policy`。`error.details` 通常包含：

```json
{
  "action": "deny",
  "code": "policy_denied",
  "ruleId": "hard-bash",
  "surface": "ssh_exec",
  "reason": "不允许调用 shell 解释器"
}
```

求值顺序是 **deny > confirm > allow**；内置硬拒绝（`hard-*`）不能被普通 allow
规则覆盖。常见误拦：

| ruleId / code | 触发示例 | 处理 |
| --- | --- | --- |
| `hard-bash` / `hard-sh` | `bash -lc '...'`、`sh script.sh` | 直接执行目标程序，或用 `ssh_sudo` |
| `hard-sudo` | 在 `ssh_exec` 中运行 `sudo ...` | 使用 `ssh_sudo` 工具 |
| `hard-curl` / `hard-wget` | 下载脚本 | 在受控环境下载后分步执行 |
| `authorized-keys-write` | 写 `authorized_keys` | 使用专门的密钥管理流程 |
| `rm-rf-root` / `rm-rf-home` | 递归删除 `/` 或 `$HOME` | 缩小路径；这类规则不应放开 |
| `policy_not_allowed` | 配置了非空 `allow`，但命令片段不匹配 | 精确补充 allow 规则 |
| `policy_confirm` | 命中 `confirm` 正则；当前没有交互式确认流程，等同拒绝 | 换用明确、无歧义的命令 |

`allow`/`deny`/`confirm` 的写法：`prefix:systemctl`、`re:...`，裸字符串按前缀处理。
规则按命令片段（`;`、`&&`、`|`、换行等分隔）逐段匹配；用解释器/包装器绕过检查会被
内置规则拒绝。

`security.command_policy.mode=off` 会关闭整个策略层（包括硬拒绝），风险很高：
它适合临时兼容旧配置，不应作为长期方案。`read_only` 会额外拒绝重定向、后台执行、
命令替换和敏感环境变量，并直接拒绝 `session_send`/`ssh_sudo`。

拒绝事件仍会写入 `audit.jsonl`（`outcome=denied`、`denied=true`），可用于核对是
哪条规则拦下的。策略是启发式防护，不是沙箱，详见
[security-threat-model.md](security-threat-model.md)。

## 8. 文件传输

单文件走 SFTP，目录走 tar over SSH；两者都会做 SHA-256/清单校验，并在目标同目录
使用临时文件后原子替换。

| 现象 / code | 可能原因 | 处理 |
| --- | --- | --- |
| `Policy` / `transfer_disabled` | `files` 配置缺失或 `local_roots` 为空 | 配置 `files.local_roots` 与大小限制 |
| 本地路径被拒绝 | 本地路径不在 `local_roots` 下 | 把根目录调整为实际工作目录 |
| 远端路径被拒绝 | 命中 `files.remote_deny` | 换路径，或调整 deny 列表 |
| SFTP 失败 | sshd 未配置 `Subsystem sftp` | 预检 `sftp-subsystem`；修复 sshd 配置后重启 |
| `tar_failed` / `remote_manifest_failed` | 远端 tar 非 GNU、权限不足、磁盘满 | 预检 `tar`/`disk`；确认目标目录可写 |
| `transfer_timeout` / `timeout` | 大目录或链路慢 | 调大 `files.transfer_timeout_ms`、`defaults.timeouts` |
| 校验失败 | 传输中被修改、磁盘满、临时文件残留 | 检查磁盘与审计；重试并确认目标可写 |
| `local_io_error` | 本地路径是目录/无权限/父目录不存在 | 检查本地路径与 ACL |
| `remote_cleanup_refused` | 清理路径安全校验拒绝 | 不要指向受保护目录；检查 deny 列表 |

排查建议：

1. 先在远端确认 `tar --version` 为 GNU tar，`sha256sum` 可用（预检会检查）。
2. 确认 `df -h` 在目标分区有足够空间；目录传输会在目标同目录创建临时文件。
3. 目录超过 `max_files`/`max_total_bytes`/`max_depth` 会被策略拒绝，按实际规模调整。
4. 符号链接按链接本身保留，不跟随；Windows 上解压符号链接不受支持。
5. 上传/下载默认 `overwrite=false`；需要覆盖时显式传 `overwrite: true`。

## 9. 配置校验

只读校验器：

```powershell
node scripts/check-config.mjs
node scripts/check-config.mjs --config "$HOME\.remote-mcp\config.yaml" --json
node scripts/check-config.mjs --require-trusted web1
```

| 退出码 | 含义 |
| --- | --- |
| 0 | 通过 |
| 2 | 用法错误，或 `dist` 未构建 |
| 3 | 配置缺失/IO/解析/schema 错误，或信任注册表损坏 |
| 4 | `--require-trusted` 指定的 alias 未受信任 |

常见 schema 问题：

- `version` 必须是 `1`；未知字段会被拒绝（配置是 strict object）。
- `hosts` 至少一台；alias 必须匹配 `^[a-z0-9][a-z0-9._-]{0,63}$`，且不能是
  `default`、`serve`、`trust` 等保留字。
- `user` 不能以 `-` 开头；`port` 为 1–65535。
- `files.max_file_bytes` 不能大于 `max_total_bytes`。
- `defaults.sudo.mode=password` 时建议同时配置 `credential`。
- `command_policy` 的 `re:` 规则必须是合法正则；YAML 双引号中的反斜杠要转义。

校验器不会联网、不会读取或打印凭据，也不会修改配置。

## 10. 升级、移动仓库与卸载

- **升级**：拉取代码后重新运行 `install.ps1`。已有配置不会被覆盖；依赖/构建过期时
  会自动重装或重建。注册更新后重启 Claude Code。
- **移动仓库**：`install.json` 与 MCP 注册保存的是绝对路径。移动后在新位置重新运行
  `install.ps1`；只复制 `dist` 而不更新注册会继续指向旧路径。
- **换 Node 版本/路径**：重新运行 `install.ps1` 会写入新的 `node.exe` 绝对路径。
- **保留数据**：`~/.remote-mcp` 下的配置、信任记录和审计不会被升级删除。
- **卸载**：

  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1 -DryRun
  powershell -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1
  ```

  默认只移除 MCP 注册和 `install.json`，保留数据。`-RemoveData` 会先做安全校验，
  非交互环境还需要 `-Yes`；它不会删除 `~/.ssh`、`dist`、`node_modules`。

- **E2E 与升级**：升级后先跑 `scripts/e2e.ps1 -DryRun`，再跑 `-UnitOnly` 和真实主机层，
  确认注册、配置与远端仍一致。用法见 [README](../README.md#端到端测试e2e)。
