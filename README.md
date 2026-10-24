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

## 安装 / 升级 / 卸载（Windows）

要求 Windows PowerShell 5.1、Node.js >= 24、npm、Claude Code CLI（`claude.cmd`）和 `ssh.exe`。
安装只写当前用户目录，不需要管理员权限。

### 快速开始

在仓库根目录运行：

```powershell
# 先做只读检查
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -DryRun

# 真实安装/升级
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
```

安装脚本会：

1. 检查 PowerShell、Node.js >= 24、npm、`claude`、`ssh` 和仓库文件；
2. 按需执行 `npm ci` 与 `npm run build`；
3. 运行 `node dist/cli.js --version`；
4. 校验已有配置；已有配置非法时只告警，不会覆盖；
5. 把 `config.example.yaml` 复制到 `~/.remote-mcp/`；上游样例变化时写 `config.example.yaml.new`，不覆盖旧文件；
6. 若 `config.yaml` 不存在且未指定 `-NoConfig`，从样例生成，并在文件头注明“示例主机必须替换”；
7. 以 user scope 注册 `remote-mcp`，命令为绝对 `node.exe` + `dist/cli.js` + `--config <绝对路径>`；
8. 运行 `claude mcp list` 检查 Connected（默认重试 2 次）；
9. 写入 `%LOCALAPPDATA%\remote-mcp\install.json`。

首次安装完成后：

```powershell
# 编辑配置，替换 hosts 中的示例地址/用户/密钥路径
notepad $HOME\.remote-mcp\config.yaml

# 固定主机密钥（把 web1 换成你的 alias）
node .\dist\cli.js trust web1

# 仅 sudo password 模式需要：把密码写入系统凭据库
# 密码从 stdin 读取（不会进入 argv），用法见下文“凭据（sudo 密码）”
node .\dist\cli.js credential set sudo.web1
```

最后重启 Claude Code，使 MCP 注册生效。安装脚本不会自动 trust 主机、不会写入密码、也不会修改远端。

### install.ps1 参数

| 参数 | 说明 |
| --- | --- |
| `-DryRun` / `-WhatIf` | 只读检查，打印 `[OK]` / `[WOULD]` / `[SKIP]`；不运行 npm、不建目录、不注册、不写状态、不跑 `mcp list` |
| `-ConfigPath <path>` | 指定配置文件（默认 `~/.remote-mcp/config.yaml`），注册时使用其绝对路径 |
| `-NoConfig` | 不生成配置；仍会复制配置样例 |
| `-SkipDeps` | 跳过 `npm ci` |
| `-ReinstallDeps` | 强制重新执行 `npm ci` |
| `-SkipBuild` | 跳过 `npm run build` |
| `-SkipRegister` | 不更新 MCP 注册 |
| `-NoVerify` | 跳过 `claude mcp list` 健康检查 |
| `-NodePath <path>` | 指定 `node.exe`（默认从 PATH 解析） |
| `-LogPath <file>` | 追加安装日志到指定文件 |

### uninstall.ps1

```powershell
# 默认：移除 MCP 注册 + 删除 install.json；保留 ~/.remote-mcp 全部数据
powershell -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1 -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1

# 同时删除数据目录（交互式确认）
powershell -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1 -RemoveData
```

| 参数 | 说明 |
| --- | --- |
| `-DryRun` / `-WhatIf` | 只读检查，不修改注册/状态/数据 |
| `-RemoveData` | 删除数据目录（默认是 `~/.remote-mcp`） |
| `-Yes` | 非交互环境删除数据时必需 |
| `-ConfigPath <path>` | 指定配置路径，从而确定数据目录 |
| `-ForcePath` | 数据目录不在用户主目录下时，确认允许删除 |

`-RemoveData` 会先做安全校验：拒绝盘符根目录、用户主目录、仓库根目录及其上级、重解析点（符号链接/联接），以及 `~/.ssh`、`~/.claude`、`dist`、`node_modules`、`src` 等受保护目录。
按配置中的 `credential` 引用尽力执行 `credential delete`；不会删除 `~/.ssh`、`dist` 或 `node_modules`。

### 退出码

`install.ps1`：

| 退出码 | 含义 |
| --- | --- |
| 0 | 成功 |
| 2 | 参数用法错误 |
| 3 | 环境前置条件不满足（PowerShell/Node/npm/claude/ssh/仓库文件） |
| 4 | 依赖安装、构建或 CLI 版本检查失败 |
| 5 | 配置生成或校验失败 |
| 6 | MCP 注册更新失败 |
| 7 | `claude mcp list` 未显示 Connected |
| 8 | 安装状态写入失败 |

`uninstall.ps1`：

| 退出码 | 含义 |
| --- | --- |
| 0 | 成功 |
| 2 | 参数用法错误或未确认删除 |
| 3 | 数据目录安全校验失败 |
| 4 | MCP 注册移除失败 |
| 5 | 安装状态或数据目录删除失败 |

### 升级与移动仓库

- 升级：拉取代码后重新运行 `install.ps1`。依赖齐全、`dist` 未过期时对应步骤显示 `[SKIP]`；不会覆盖已有配置。
- 移动仓库：在新位置运行 `install.ps1`，注册会更新为新的绝对 `node.exe`、`dist/cli.js` 与配置路径，`install.json` 也会刷新。
- 修改源码后重新运行 `install.ps1` 会自动检测并重新构建；也可先手动 `npm run build`。
- 每次更新注册后重启 Claude Code。

## Ubuntu 远端预检（只读）

`scripts/ubuntu-preflight.sh` 在作为远端的 Ubuntu 主机上运行，检查 SSH、SFTP、
权限、bash/coreutils、tar/校验工具、sudo、locale、磁盘和防火墙。它**不写文件、
不修改 sudoers、不调用包管理器**；默认也完全不执行 sudo。

```bash
# 在远端主机上
bash ubuntu-preflight.sh
bash ubuntu-preflight.sh --json
bash ubuntu-preflight.sh --sudo-probe --min-free-mb 2048 --user deploy
```

也可以从本机直接跑：

```powershell
# 先上传到远端临时目录，再执行（示例）
scp .\scripts\ubuntu-preflight.sh orangepi:/tmp/ubuntu-preflight.sh
ssh orangepi 'chmod 755 /tmp/ubuntu-preflight.sh && /tmp/ubuntu-preflight.sh --json'
```

| 参数 | 说明 |
| --- | --- |
| `--json` | stdout 只输出 JSON；人类可读内容被抑制 |
| `--min-free-mb <N>` | 用户 home 所在文件系统的最小可用空间，默认 1024 MiB |
| `--user <name>` | 要检查的用户，默认当前用户 |
| `--sudo-probe` | 额外执行无副作用的 `sudo -n true`（以及只读防火墙状态查询） |
| `-h` / `--help` | 显示帮助 |

输出标记为 `[OK]` / `[WARN]` / `[FAIL]` / `[SKIP]`，并附带建议。退出码：

| 退出码 | 含义 |
| --- | --- |
| 0 | 没有 `FAIL`（可以有 `WARN`/`SKIP`） |
| 1 | 存在必需项 `FAIL` |
| 2 | 参数用法错误 |

检查项包括：OS、sshd 版本/服务/端口、`Subsystem sftp`、`PubkeyAuthentication`、
home 与 `~/.ssh` 权限、`authorized_keys` 0600、bash 版本、coreutils
（`stat`/`mktemp`/`mv`/`chmod`/`realpath` 或 `readlink -f`/`base64`/`tr`/`head`/
`printf`/`uname`/`id`）、GNU tar、`sha256sum`（回退 `shasum`/`openssl`）、sudo 与
组、locale、磁盘、防火墙。无 root 权限时防火墙检查标为 `SKIP`。

## 端到端测试（E2E）

`scripts/e2e.ps1` 按层运行测试并输出汇总表；带有 `-Json` / `-ReportPath` 时可生成
机器可读报告。测试计数来自 Vitest 的 JSON reporter，不使用文本正则。
运行 Vitest 时脚本会把 Git 的 `usr\bin` 前置到 PATH，确保单元测试使用 Git Bash
而不是 WindowsApps 下的 WSL `bash`。

```powershell
npm run e2e                              # 前置检查 + 构建 + unit + protocol
npm run e2e -- -DryRun                   # 只打印计划，不执行任何层
npm run e2e -- -UnitOnly                 # 只跑 unit + protocol
npm run e2e -- -Real -Alias orangepi     # 显式要求真实主机层
npm run e2e -- -Json -ReportPath .\e2e-report.json
```

| 层 | 内容 |
| --- | --- |
| Prerequisites | Node.js >= 24、npm、`ssh`、Vitest、仓库文件 |
| Build | `npm run build`（`-NoBuild` 时要求 `dist/cli.js` 已存在） |
| Unit | `vitest run test/unit` |
| Protocol | `vitest run test/protocol` |
| Real host | 校验配置/alias/trust 后运行 `vitest run test/integration` |
| Container | 仅当 `docker info` 可用：在 `ubuntu:24.04` 容器中检查预检脚本与工具链 |
| VM | 仅当显式 `-Multipass` 且 multipass 已安装；实例名固定为 `remote-mcp-e2e` |

| 参数 | 说明 |
| --- | --- |
| `-DryRun` | 不执行任何层，只打印计划状态 |
| `-NoBuild` | 跳过构建 |
| `-UnitOnly` | 只运行 Unit + Protocol（其余层 `SKIP`） |
| `-NoReal` / `-Real` | 跳过/强制真实主机层；两者不能同时使用 |
| `-Alias <name>` | 真实主机 alias，默认 `orangepi`；同时设置 `REMOTE_MCP_E2E_ALIAS` |
| `-ConfigPath <path>` | 真实主机配置，默认 `REMOTE_MCP_CONFIG` 或 `~/.remote-mcp/config.yaml` |
| `-NoContainers` / `-RequireContainers` | 跳过 Container / Docker 不可用时直接 FAIL |
| `-Multipass` | 允许 VM 层 |
| `-TimeoutMin <n>` | 每层超时，默认 30 分钟 |
| `-Json` | stdout 只输出 JSON 报告 |
| `-ReportPath <file>` | 写入 JSON 报告（UTF-8，无 BOM） |

真实主机层的前置条件：

- 设置 `REMOTE_MCP_E2E=1` 或显式传 `-Real`；
- 配置中必须存在 `-Alias` 指定的 host，且该 alias 已在 `trusted.json` 中固定；
- 缺配置/alias/trust 时，**未显式 `-Real`** 则 `SKIP` 并打印修复命令；
  **显式 `-Real`** 则 `FAIL`，退出码 3。
- 测试通过环境变量 `REMOTE_MCP_E2E=1`、`REMOTE_MCP_E2E_ALIAS`、
  `REMOTE_MCP_CONFIG` 运行，不修改真实配置；指纹期望值可用
  `REMOTE_MCP_E2E_FINGERPRINT` 覆盖。

`SKIP` 的含义是该层没有可执行条件（例如未请求真实主机、Docker/Multipass 不可用），
**不是失败**；`-RequireContainers` 可把“Docker 不可用”从 `SKIP` 提升为 `FAIL`。
`-DryRun` 的 `WOULD` 表示“若实际运行将执行此层”。链路上行较慢时
`host_check` 的首次 8 秒检查可能超时；这是可重试错误，重跑一次真实主机层即可。

| 退出码 | 含义 |
| --- | --- |
| 0 | 所有已执行层 PASS 或 SKIP |
| 1 | 某个已执行层 FAIL（构建/测试/容器/VM） |
| 2 | 参数用法错误 |
| 3 | 前置条件失败，或显式 `-Real` 时真实主机前置条件缺失 |
| 4 | 报告写入失败 |

## 故障排查

常见问题（MCP 未连接、host key/trust/rotate、认证/agent、sudo、编码、防火墙、
策略误拦、文件传输、配置校验、升级/移动路径）见
[docs/troubleshooting.md](docs/troubleshooting.md)。

快速自检：

```powershell
claude mcp list
node scripts/check-config.mjs --json
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/e2e.ps1 -UnitOnly
```

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
      # YAML 双引号里反斜杠需要写成 \\，否则 \b 会被解释为退格
      - "re:\\b(shutdown|reboot)\\b"
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
