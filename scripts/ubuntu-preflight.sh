#!/usr/bin/env bash
#
# remote-mcp Ubuntu 预检（只读）。
#
# 目标：在作为 remote-mcp 远端的 Ubuntu 主机上运行，确认 SSH/SFTP/工具链满足要求。
# 安全约束：
#   - 不写任何文件（不使用 mktemp/重定向到文件），不修改 sudoers，不调用包管理器；
#   - 默认不执行 sudo；只有显式 --sudo-probe 时执行无副作用命令（sudo -n true、
#     只读的 ufw/firewall-cmd/nft 状态查询）；
#   - 输出中的建议只是文字，脚本不会代为执行。
#
# 退出码：
#   0  没有 FAIL（可能有 WARN/SKIP）
#   1  存在必需项 FAIL
#   2  参数用法错误
#
# 用法：bash ubuntu-preflight.sh [--json] [--min-free-mb N] [--user NAME] [--sudo-probe]

set -u

PROG=$(basename -- "$0")
MIN_FREE_MB=1024
TARGET_USER=''
SUDO_PROBE=0
JSON_OUTPUT=0

CHECK_IDS=()
CHECK_STATUS=()
CHECK_DETAIL=()
CHECK_ADVICE=()

OK_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

SUDO_NOPASSWD=0

usage() {
    cat <<'EOF'
用法: bash ubuntu-preflight.sh [选项]

只读检查一台 Ubuntu 主机是否满足 remote-mcp 的 SSH / SFTP / 工具链要求。
脚本不会写文件、不会修改 sudoers，也不会安装软件。

选项:
  --json                 以 JSON 输出（stdout 只有 JSON，便于脚本解析）
  --min-free-mb <N>      用户主目录所在文件系统的最小可用空间，默认 1024 MiB
  --user <name>          要检查的用户，默认当前用户
  --sudo-probe           额外探测 sudo 是否可无密码执行；只运行无副作用命令
  -h, --help             显示本帮助

输出标记:
  [OK]   满足要求
  [WARN] 可能需要人工确认，但不阻止使用
  [FAIL] 必需项不满足（退出码 1）
  [SKIP] 环境无法判断（例如权限不足）

退出码: 0 无 FAIL / 1 存在 FAIL / 2 用法错误
EOF
}

usage_error() {
    printf '%s: %s\n' "$PROG" "$1" >&2
    printf '运行 bash %s --help 查看用法。\n' "$PROG" >&2
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --json)
            JSON_OUTPUT=1
            shift
            ;;
        --min-free-mb)
            [ "$#" -ge 2 ] || usage_error '--min-free-mb 需要参数'
            MIN_FREE_MB=$2
            shift 2
            ;;
        --min-free-mb=*)
            MIN_FREE_MB=${1#*=}
            shift
            ;;
        --user)
            [ "$#" -ge 2 ] || usage_error '--user 需要参数'
            TARGET_USER=$2
            shift 2
            ;;
        --user=*)
            TARGET_USER=${1#*=}
            shift
            ;;
        --sudo-probe)
            SUDO_PROBE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage_error "未知参数: $1"
            ;;
    esac
done

case "$MIN_FREE_MB" in
    ''|*[!0-9]*)
        usage_error '--min-free-mb 必须是非负整数'
        ;;
esac

if [ -n "$TARGET_USER" ]; then
    case "$TARGET_USER" in
        -*|*[!A-Za-z0-9._-]*)
            usage_error '--user 只能包含字母、数字、点、下划线或连字符，且不能以 - 开头'
            ;;
    esac
fi

have() {
    command -v "$1" >/dev/null 2>&1
}

add_result() {
    local id=$1
    local status=$2
    local detail=$3
    local advice=${4:-}

    CHECK_IDS[${#CHECK_IDS[@]}]=$id
    CHECK_STATUS[${#CHECK_STATUS[@]}]=$status
    CHECK_DETAIL[${#CHECK_DETAIL[@]}]=$detail
    CHECK_ADVICE[${#CHECK_ADVICE[@]}]=$advice

    case "$status" in
        OK) OK_COUNT=$((OK_COUNT + 1)) ;;
        WARN) WARN_COUNT=$((WARN_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
    esac

    if [ "$JSON_OUTPUT" -eq 0 ]; then
        printf '[%s] %s: %s\n' "$status" "$id" "$detail"
        if [ -n "$advice" ]; then
            printf '       建议: %s\n' "$advice"
        fi
    fi
}

json_escape() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

stat_mode() {
    stat -c '%a' -- "$1" 2>/dev/null || true
}

stat_owner() {
    stat -c '%U' -- "$1" 2>/dev/null || true
}

# 返回 0 表示组或其他用户可写（sshd StrictModes 会拒绝）。
mode_group_or_other_writable() {
    local mode=$1
    [ -n "$mode" ] || return 1
    [ $((0$mode & 022)) -ne 0 ]
}

sshd_subsystem_line() {
    local file
    for file in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [ -r "$file" ] || continue
        grep -h -i -E '^[[:space:]]*Subsystem[[:space:]]+sftp[[:space:]]+' "$file" 2>/dev/null || true
    done
}

if [ -z "$TARGET_USER" ]; then
    TARGET_USER=$(id -un 2>/dev/null || true)
fi

if [ "$JSON_OUTPUT" -eq 0 ]; then
    printf 'remote-mcp Ubuntu 预检（只读）\n'
    printf 'host=%s user=%s\n\n' "$(uname -n 2>/dev/null || echo unknown)" "$TARGET_USER"
fi

# ---------------------------------------------------------------------------
# 1. OS
# ---------------------------------------------------------------------------

KERNEL=$(uname -s 2>/dev/null || echo unknown)
OS_NAME='unknown'
OS_VERSION=''
if [ -r /etc/os-release ]; then
    while IFS='=' read -r key value; do
        value=${value%\"}
        value=${value#\"}
        case "$key" in
            NAME) OS_NAME=$value ;;
            VERSION_ID) OS_VERSION=$value ;;
        esac
    done < /etc/os-release
fi

if [ "$KERNEL" = 'Linux' ]; then
    detail="$OS_NAME ${OS_VERSION:+$OS_VERSION }(kernel $(uname -r 2>/dev/null || echo '?'))"
    case "$OS_NAME" in
        *Ubuntu*|*Debian*)
            add_result 'os' 'OK' "$detail"
            ;;
        *)
            add_result 'os' 'WARN' "$detail" 'remote-mcp 主要按 Ubuntu/Debian 验证；其他发行版请自行确认工具路径。'
            ;;
    esac
else
    add_result 'os' 'FAIL' "内核为 $KERNEL，不是 Linux" '本预检面向 Ubuntu 远端主机。'
fi

# ---------------------------------------------------------------------------
# 2. 用户与 home
# ---------------------------------------------------------------------------

if [ -z "$TARGET_USER" ]; then
    add_result 'user' 'FAIL' '无法确定要检查的用户（id -un 失败且未指定 --user）' '使用 --user <name> 指定用户。'
    TARGET_HOME=''
else
    TARGET_HOME=''
    if have getent; then
        TARGET_HOME=$(getent passwd "$TARGET_USER" 2>/dev/null | awk -F: 'NR == 1 { print $6 }')
    fi
    if [ -z "$TARGET_HOME" ] && [ -r /etc/passwd ]; then
        TARGET_HOME=$(awk -F: -v u="$TARGET_USER" '$1 == u { print $6; exit }' /etc/passwd)
    fi

    if [ -n "$TARGET_HOME" ]; then
        add_result 'user' 'OK' "$TARGET_USER (home=$TARGET_HOME)"
    else
        add_result 'user' 'FAIL' "用户 $TARGET_USER 不存在或无法读取其 home" '检查 --user 拼写，或确认该用户已创建。'
    fi
fi

if [ -n "$TARGET_HOME" ] && [ -d "$TARGET_HOME" ]; then
    home_mode=$(stat_mode "$TARGET_HOME")
    if [ -n "$home_mode" ] && mode_group_or_other_writable "$home_mode"; then
        add_result 'home-perm' 'FAIL' "$TARGET_HOME 权限为 $home_mode（组或其他用户可写）" \
            "chmod go-w $TARGET_HOME（sshd StrictModes 会拒绝组/其他用户可写的 home）。"
    elif [ -n "$home_mode" ] && [ "$home_mode" != '700' ]; then
        add_result 'home-perm' 'WARN' "$TARGET_HOME 权限为 $home_mode" \
            "chmod 700 $TARGET_HOME；至少确保组/其他用户不可写。"
    elif [ -n "$home_mode" ]; then
        add_result 'home-perm' 'OK' "$TARGET_HOME 权限为 $home_mode"
    else
        add_result 'home-perm' 'SKIP' "无法读取 $TARGET_HOME 的权限"
    fi
elif [ -n "$TARGET_HOME" ]; then
    add_result 'home-perm' 'FAIL' "$TARGET_HOME 不存在或不是目录" '确认用户 home 已创建。'
else
    add_result 'home-perm' 'SKIP' '未确定用户 home'
fi

# ---------------------------------------------------------------------------
# 3. sshd：安装、版本、服务、端口、子系统、公钥认证
# ---------------------------------------------------------------------------

SSHD_BIN=''
if have sshd; then
    SSHD_BIN=$(command -v sshd)
elif [ -x /usr/sbin/sshd ]; then
    SSHD_BIN=/usr/sbin/sshd
fi

if [ -z "$SSHD_BIN" ]; then
    add_result 'sshd' 'FAIL' '未找到 sshd 可执行文件' '安装 openssh-server（本脚本不会代你安装）。'
else
    sshd_version=$("$SSHD_BIN" -V 2>&1 | head -n 1 || true)
    case "$sshd_version" in
        OpenSSH*) ;;
        *)
            sshd_version=$(ssh -V 2>&1 | head -n 1 || true)
            ;;
    esac
    if [ -n "$sshd_version" ]; then
        add_result 'sshd' 'OK' "$SSHD_BIN ($sshd_version)"
    else
        add_result 'sshd' 'WARN' "$SSHD_BIN 已安装，但无法读取版本"
    fi
fi

SSHD_T=''
if [ -n "$SSHD_BIN" ]; then
    SSHD_T=$("$SSHD_BIN" -T 2>/dev/null || true)
fi

if have systemctl; then
    if systemctl is-active --quiet ssh 2>/dev/null; then
        add_result 'sshd-service' 'OK' 'ssh.service 正在运行'
    elif systemctl is-active --quiet sshd 2>/dev/null; then
        add_result 'sshd-service' 'OK' 'sshd.service 正在运行'
    else
        state=$(systemctl is-active ssh 2>/dev/null || true)
        add_result 'sshd-service' 'FAIL' "ssh.service 未运行（state=${state:-unknown}）" \
            'sudo systemctl enable --now ssh'
    fi

    if systemctl is-enabled --quiet ssh 2>/dev/null || systemctl is-enabled --quiet sshd 2>/dev/null; then
        add_result 'sshd-enabled' 'OK' 'sshd 已设为开机启动'
    else
        add_result 'sshd-enabled' 'WARN' 'sshd 未设为开机启动' 'sudo systemctl enable ssh'
    fi
elif have pgrep; then
    if pgrep -x sshd >/dev/null 2>&1; then
        add_result 'sshd-service' 'OK' '检测到 sshd 进程（无 systemd）'
    else
        add_result 'sshd-service' 'WARN' '未检测到 sshd 进程（系统可能未使用 systemd）' '确认 sshd 由其他方式启动。'
    fi
else
    add_result 'sshd-service' 'SKIP' '无法判断服务状态（缺少 systemctl/pgrep）'
fi

PORTS=''
if [ -n "$SSHD_T" ]; then
    PORTS=$(printf '%s\n' "$SSHD_T" | awk 'tolower($1) == "port" { print $2 }')
fi
if [ -z "$PORTS" ]; then
    for file in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [ -r "$file" ] || continue
        PORTS="$PORTS $(awk 'tolower($1) == "port" { print $2 }' "$file" 2>/dev/null || true)"
    done
fi
PORTS=$(printf '%s\n' "$PORTS" | tr ' ' '\n' | awk 'NF' | sort -nu | tr '\n' ' ' | sed 's/[[:space:]]*$//')
if [ -z "$PORTS" ]; then
    PORTS='22'
fi
FIRST_PORT=${PORTS%% *}

if [ -z "$SSHD_BIN" ]; then
    add_result 'sshd-port' 'SKIP' 'sshd 未安装，无法确定监听端口'
else
    add_result 'sshd-port' 'OK' "监听端口: $PORTS" \
        "remote-mcp 配置中的 port 必须与之匹配（当前配置默认 22）。"
fi

SFTP_PATH=''
if [ -n "$SSHD_T" ]; then
    SFTP_PATH=$(printf '%s\n' "$SSHD_T" | awk 'tolower($1) == "subsystem" && $2 == "sftp" { print $3; exit }')
fi
if [ -z "$SFTP_PATH" ]; then
    SFTP_PATH=$(sshd_subsystem_line | awk '{ print $3; exit }')
fi

if [ -n "$SFTP_PATH" ]; then
    add_result 'sftp-subsystem' 'OK' "Subsystem sftp $SFTP_PATH"
else
    add_result 'sftp-subsystem' 'FAIL' 'sshd 未配置 Subsystem sftp' \
        '在 sshd_config 中加入 `Subsystem sftp /usr/lib/openssh/sftp-server` 后重启 sshd；否则单文件上传/下载不可用。'
fi

PUBKEY=''
if [ -n "$SSHD_T" ]; then
    PUBKEY=$(printf '%s\n' "$SSHD_T" | awk 'tolower($1) == "pubkeyauthentication" { print $2; exit }')
fi
if [ -z "$PUBKEY" ]; then
    if grep -h -i -E '^[[:space:]]*PubkeyAuthentication[[:space:]]+no([[:space:]]|$)' \
        /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -q .; then
        PUBKEY='no'
    else
        PUBKEY='yes (default)'
    fi
fi
case "$PUBKEY" in
    no|NO|No)
        add_result 'pubkey-auth' 'FAIL' 'PubkeyAuthentication=no' \
            '改为 yes（或删除该行使用默认值）；remote-mcp 依赖公钥认证。'
        ;;
    *)
        add_result 'pubkey-auth' 'OK' "PubkeyAuthentication=$PUBKEY"
        ;;
esac

# ---------------------------------------------------------------------------
# 4. ~/.ssh 与 authorized_keys
# ---------------------------------------------------------------------------

if [ -n "$TARGET_HOME" ]; then
    SSH_DIR="$TARGET_HOME/.ssh"
    if [ ! -d "$SSH_DIR" ]; then
        add_result 'ssh-dir' 'WARN' "$SSH_DIR 不存在" \
            "mkdir -m 700 $SSH_DIR；未配置公钥时只能使用密码或 agent 认证。"
    else
        ssh_mode=$(stat_mode "$SSH_DIR")
        ssh_owner=$(stat_owner "$SSH_DIR")
        if [ -n "$ssh_mode" ] && mode_group_or_other_writable "$ssh_mode"; then
            add_result 'ssh-dir' 'FAIL' "$SSH_DIR 权限为 $ssh_mode（组或其他用户可写）" \
                "chmod 700 $SSH_DIR（sshd StrictModes 会拒绝）。"
        elif [ -n "$ssh_mode" ] && [ "$ssh_mode" != '700' ]; then
            add_result 'ssh-dir' 'WARN' "$SSH_DIR 权限为 $ssh_mode" "建议 chmod 700 $SSH_DIR。"
        elif [ -z "$ssh_mode" ]; then
            add_result 'ssh-dir' 'SKIP' "无法读取 $SSH_DIR 的权限（可能被 home 权限阻止）"
        else
            detail="$SSH_DIR 权限为 ${ssh_mode:-?}"
            if [ -n "$ssh_owner" ] && [ "$ssh_owner" != "$TARGET_USER" ]; then
                add_result 'ssh-dir' 'WARN' "$detail，owner=$ssh_owner" "chown -R $TARGET_USER:$TARGET_USER $SSH_DIR"
            else
                add_result 'ssh-dir' 'OK' "$detail"
            fi
        fi

        AUTH_KEYS="$SSH_DIR/authorized_keys"
        if [ ! -e "$AUTH_KEYS" ]; then
            add_result 'authorized-keys' 'WARN' "$AUTH_KEYS 不存在" \
                "如需公钥登录，写入你的公钥（本脚本不会修改该文件）。"
        else
            ak_mode=$(stat_mode "$AUTH_KEYS")
            ak_owner=$(stat_owner "$AUTH_KEYS")
            if [ -n "$ak_mode" ] && mode_group_or_other_writable "$ak_mode"; then
                add_result 'authorized-keys' 'FAIL' "$AUTH_KEYS 权限为 $ak_mode（组或其他用户可写）" \
                    "chmod 600 $AUTH_KEYS；sshd 会忽略组/其他用户可写的 authorized_keys。"
            elif [ -n "$ak_mode" ] && [ "$ak_mode" != '600' ]; then
                add_result 'authorized-keys' 'WARN' "$AUTH_KEYS 权限为 $ak_mode" "建议 chmod 600 $AUTH_KEYS。"
            elif [ -z "$ak_mode" ]; then
                add_result 'authorized-keys' 'SKIP' "无法读取 $AUTH_KEYS 的权限"
            elif [ ! -s "$AUTH_KEYS" ]; then
                add_result 'authorized-keys' 'WARN' "$AUTH_KEYS 为空" '写入至少一个公钥，或改用其他认证方式。'
            elif [ -n "$ak_owner" ] && [ "$ak_owner" != "$TARGET_USER" ] && [ "$ak_owner" != 'root' ]; then
                add_result 'authorized-keys' 'WARN' "$AUTH_KEYS owner=$ak_owner" \
                    "chown $TARGET_USER:$TARGET_USER $AUTH_KEYS"
            else
                add_result 'authorized-keys' 'OK' "$AUTH_KEYS 权限为 $ak_mode，owner=${ak_owner:-?}"
            fi
        fi
    fi
else
    add_result 'ssh-dir' 'SKIP' '未确定用户 home'
    add_result 'authorized-keys' 'SKIP' '未确定用户 home'
fi

# ---------------------------------------------------------------------------
# 5. bash 与工具链
# ---------------------------------------------------------------------------

if ! have bash; then
    add_result 'bash' 'FAIL' '未找到 bash' '安装 bash；remote-mcp 通过 bash -lc 执行远端命令。'
else
    bash_version=$(bash -c 'printf "%s.%s" "${BASH_VERSINFO[0]:-0}" "${BASH_VERSINFO[1]:-0}"' 2>/dev/null || true)
    bash_major=${bash_version%%.*}
    bash_minor=${bash_version#*.}
    case "$bash_major" in ''|*[!0-9]*) bash_major=0 ;; esac
    case "$bash_minor" in ''|*[!0-9]*) bash_minor=0 ;; esac
    if [ "$bash_major" -lt 4 ]; then
        add_result 'bash' 'WARN' "bash $bash_version" '建议 bash >= 4.0；更旧的版本可能缺少部分展开语法。'
    else
        add_result 'bash' 'OK' "bash $bash_version ($(command -v bash))"
    fi
fi

MISSING_TOOLS=''
for tool in stat mktemp mv chmod base64 tr head printf uname id; do
    if ! have "$tool"; then
        MISSING_TOOLS="$MISSING_TOOLS $tool"
    fi
done

REALPATH_MODE=''
if have realpath; then
    REALPATH_MODE='realpath'
elif have readlink && readlink -f / >/dev/null 2>&1; then
    REALPATH_MODE='readlink -f'
else
    MISSING_TOOLS="$MISSING_TOOLS realpath(readlink -f)"
fi

if [ -n "$MISSING_TOOLS" ]; then
    add_result 'coreutils' 'FAIL' "缺少:$MISSING_TOOLS" \
        '安装 coreutils（以及提供 readlink -f 的 coreutils 版本）；传输与原子替换依赖这些工具。'
else
    add_result 'coreutils' 'OK' "stat/mktemp/mv/chmod/base64/tr/head/printf/uname/id 均存在（$REALPATH_MODE）"
fi

if ! have tar; then
    add_result 'tar' 'FAIL' '未找到 tar' '安装 tar；目录上传/下载依赖 tar over SSH。'
else
    tar_version=$(tar --version 2>/dev/null | head -n 1 || true)
    case "$tar_version" in
        *GNU*) add_result 'tar' 'OK' "$tar_version" ;;
        '') add_result 'tar' 'WARN' 'tar 已安装，但无法读取版本' ;;
        *) add_result 'tar' 'WARN' "非 GNU tar: $tar_version" \
            '建议安装 GNU tar；BSD/busybox tar 的符号链接与长路径行为可能不同。' ;;
    esac
fi

if have sha256sum; then
    add_result 'checksum' 'OK' 'sha256sum 可用'
elif have shasum; then
    add_result 'checksum' 'WARN' 'sha256sum 缺失，将回退到 shasum -a 256' \
        '建议安装 coreutils 以获得 sha256sum。'
elif have openssl; then
    add_result 'checksum' 'WARN' 'sha256sum/shasum 缺失，将回退到 openssl dgst -sha256' \
        '建议安装 coreutils 以获得 sha256sum。'
else
    add_result 'checksum' 'FAIL' '缺少 sha256sum/shasum/openssl' \
        '文件传输校验依赖至少一种 SHA-256 工具。'
fi

# ---------------------------------------------------------------------------
# 6. sudo（默认不执行）
# ---------------------------------------------------------------------------

if ! have sudo; then
    add_result 'sudo' 'WARN' '未安装 sudo' 'ssh_sudo 不可用；如需 sudo 请安装并配置。'
else
    sudo_version=$(sudo --version 2>/dev/null | head -n 1 || true)
    add_result 'sudo' 'OK' "${sudo_version:-sudo $(command -v sudo)}"
fi

sudo_groups=$(id -nG "$TARGET_USER" 2>/dev/null || true)
case " $sudo_groups " in
    *' sudo '*|*' wheel '*)
        add_result 'sudo-group' 'OK' "$TARGET_USER 属于 sudo/wheel 组"
        ;;
    *)
        add_result 'sudo-group' 'WARN' "$TARGET_USER 不属于 sudo/wheel 组（groups: ${sudo_groups:-unknown}）" \
            '只有 /etc/sudoers 中显式的 NOPASSWD 规则仍可能生效；否则 ssh_sudo 会返回 SudoPrompt。'
        ;;
esac

CURRENT_USER=$(id -un 2>/dev/null || true)
if [ "$SUDO_PROBE" -ne 1 ]; then
    add_result 'sudo-probe' 'SKIP' '未指定 --sudo-probe（默认不执行 sudo）'
elif [ "$TARGET_USER" != "$CURRENT_USER" ]; then
    add_result 'sudo-probe' 'SKIP' "--sudo-probe 只探测当前用户（当前 $CURRENT_USER，检查 $TARGET_USER）" \
        '以目标用户身份重新运行脚本后再探测。'
elif ! have sudo; then
    add_result 'sudo-probe' 'SKIP' 'sudo 未安装'
else
    if LC_ALL=C sudo -n -- true >/dev/null 2>&1; then
        SUDO_NOPASSWD=1
        add_result 'sudo-probe' 'OK' 'sudo -n true 成功：passwordless sudo 可用'
    else
        add_result 'sudo-probe' 'WARN' 'sudo -n true 失败：需要密码或未配置 NOPASSWD' \
            '在 sudo.mode=password 下用 `remote-mcp credential set <ref>` 提供密码，或为需要的命令配置 NOPASSWD。'
    fi
fi

# ---------------------------------------------------------------------------
# 7. locale
# ---------------------------------------------------------------------------

if ! have locale; then
    add_result 'locale' 'SKIP' 'locale 命令不可用（精简系统）'
else
    charmap=$(locale charmap 2>/dev/null || true)
    current_locale=${LC_ALL:-${LC_CTYPE:-${LANG:-}}}
    if [ "$charmap" = 'UTF-8' ]; then
        add_result 'locale' 'OK' "字符集 UTF-8（locale=${current_locale:-unset}）"
    else
        utf8_available=''
        if locale -a 2>/dev/null | grep -qiE '^(C|en_US)\.utf-?8$'; then
            utf8_available=1
        fi
        if [ -n "$utf8_available" ]; then
            add_result 'locale' 'WARN' "当前字符集为 ${charmap:-unknown}（locale=${current_locale:-unset}）" \
                '在会话中设置 LANG=C.UTF-8 或 en_US.UTF-8；remote-mcp 本身会为命令设置 LC_ALL=C。'
        else
            add_result 'locale' 'WARN' "当前字符集为 ${charmap:-unknown}，且未找到 UTF-8 locale" \
                '生成 UTF-8 locale（例如 sudo locale-gen en_US.UTF-8）后设置 LANG。'
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 8. 磁盘
# ---------------------------------------------------------------------------

if [ -n "$TARGET_HOME" ] && have df; then
    free_mb=$(df -Pm "$TARGET_HOME" 2>/dev/null | awk 'NR == 2 { print $4 }')
    case "$free_mb" in
        ''|*[!0-9]*)
            add_result 'disk' 'SKIP' "无法读取 $TARGET_HOME 所在文件系统的可用空间"
            ;;
        *)
            if [ "$free_mb" -ge "$MIN_FREE_MB" ]; then
                add_result 'disk' 'OK' "$TARGET_HOME 可用 ${free_mb} MiB（阈值 ${MIN_FREE_MB} MiB）"
            else
                add_result 'disk' 'WARN' "$TARGET_HOME 仅剩 ${free_mb} MiB（阈值 ${MIN_FREE_MB} MiB）" \
                    '清理空间或调低传输大小；目录传输会在目标同目录创建临时文件。'
            fi
            ;;
    esac
else
    add_result 'disk' 'SKIP' '无法确定 home 或缺少 df'
fi

# ---------------------------------------------------------------------------
# 9. 防火墙（无权限时 SKIP）
# ---------------------------------------------------------------------------

firewall_checked=0

if have ufw; then
    firewall_checked=1
    fw_out=$(ufw status 2>/dev/null || true)
    if [ -z "$fw_out" ] && [ "$SUDO_NOPASSWD" -eq 1 ]; then
        fw_out=$(LC_ALL=C sudo -n ufw status 2>/dev/null || true)
    fi
    case "$fw_out" in
        *'Status: active'*)
            if printf '%s\n' "$fw_out" | grep -qE "(^|[^0-9])${FIRST_PORT}(/tcp)?([^0-9]|$)"; then
                add_result 'firewall' 'OK' "ufw 已启用，输出中出现端口 $FIRST_PORT"
            else
                add_result 'firewall' 'WARN' "ufw 已启用，但未在状态输出中看到端口 $FIRST_PORT" \
                    "确认放行：sudo ufw allow ${FIRST_PORT}/tcp（本脚本不会修改防火墙）。"
            fi
            ;;
        *'Status: inactive'*)
            add_result 'firewall' 'OK' 'ufw 已安装但未启用'
            ;;
        *)
            add_result 'firewall' 'SKIP' '无法读取 ufw 状态（需要 root）' \
                '如需确认：sudo ufw status；本脚本不会执行 sudo 以外的读取（默认完全不执行）。'
            ;;
    esac
elif have firewall-cmd; then
    firewall_checked=1
    fw_state=$(firewall-cmd --state 2>/dev/null || true)
    if [ -z "$fw_state" ] && [ "$SUDO_NOPASSWD" -eq 1 ]; then
        fw_state=$(LC_ALL=C sudo -n firewall-cmd --state 2>/dev/null || true)
    fi
    case "$fw_state" in
        running)
            add_result 'firewall' 'WARN' 'firewalld 正在运行' \
                "确认端口 $FIRST_PORT/tcp 已放行：sudo firewall-cmd --list-ports；脚本不会修改规则。"
            ;;
        'not running')
            add_result 'firewall' 'OK' 'firewalld 未运行'
            ;;
        *)
            add_result 'firewall' 'SKIP' '无法读取 firewalld 状态（需要 root）'
            ;;
    esac
elif have nft; then
    firewall_checked=1
    fw_out=$(nft list ruleset 2>/dev/null || true)
    if [ -z "$fw_out" ] && [ "$SUDO_NOPASSWD" -eq 1 ]; then
        fw_out=$(LC_ALL=C sudo -n nft list ruleset 2>/dev/null || true)
    fi
    if [ -n "$fw_out" ]; then
        add_result 'firewall' 'WARN' '检测到 nftables 规则' \
            "确认端口 $FIRST_PORT/tcp 可被访问；脚本不会修改规则。"
    else
        add_result 'firewall' 'SKIP' '无法读取 nftables 规则（需要 root 或规则为空）'
    fi
elif have iptables; then
    firewall_checked=1
    fw_out=$(iptables -S 2>/dev/null || true)
    if [ -z "$fw_out" ] && [ "$SUDO_NOPASSWD" -eq 1 ]; then
        fw_out=$(LC_ALL=C sudo -n iptables -S 2>/dev/null || true)
    fi
    if [ -n "$fw_out" ]; then
        add_result 'firewall' 'WARN' '检测到 iptables 规则' \
            "确认端口 $FIRST_PORT/tcp 可被访问；脚本不会修改规则。"
    else
        add_result 'firewall' 'SKIP' '无法读取 iptables 规则（需要 root）'
    fi
fi

if [ "$firewall_checked" -eq 0 ]; then
    add_result 'firewall' 'SKIP' '未检测到 ufw/firewalld/nftables/iptables'
fi

# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------

EXIT_CODE=0
if [ "$FAIL_COUNT" -gt 0 ]; then
    EXIT_CODE=1
fi

if [ "$JSON_OUTPUT" -eq 1 ]; then
    generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo '')
    host_name=$(uname -n 2>/dev/null || echo unknown)

    printf '{\n'
    printf '  "schemaVersion": 1,\n'
    printf '  "generatedAt": "%s",\n' "$(json_escape "$generated_at")"
    printf '  "hostname": "%s",\n' "$(json_escape "$host_name")"
    printf '  "user": "%s",\n' "$(json_escape "$TARGET_USER")"
    printf '  "home": "%s",\n' "$(json_escape "$TARGET_HOME")"
    printf '  "minFreeMb": %s,\n' "$MIN_FREE_MB"
    printf '  "sudoProbe": %s,\n' "$([ "$SUDO_PROBE" -eq 1 ] && echo true || echo false)"
    printf '  "checks": [\n'

    i=0
    total=${#CHECK_IDS[@]}
    while [ "$i" -lt "$total" ]; do
        if [ "$i" -gt 0 ]; then
            printf ',\n'
        fi
        advice=''
        if [ -n "${CHECK_ADVICE[$i]}" ]; then
            advice=$(printf '"%s"' "$(json_escape "${CHECK_ADVICE[$i]}")")
        else
            advice='null'
        fi
        printf '    {"id": "%s", "status": "%s", "detail": "%s", "advice": %s}' \
            "$(json_escape "${CHECK_IDS[$i]}")" \
            "$(json_escape "${CHECK_STATUS[$i]}")" \
            "$(json_escape "${CHECK_DETAIL[$i]}")" \
            "$advice"
        i=$((i + 1))
    done

    printf '\n  ],\n'
    printf '  "summary": {"ok": %d, "warn": %d, "fail": %d, "skip": %d, "exitCode": %d}\n' \
        "$OK_COUNT" "$WARN_COUNT" "$FAIL_COUNT" "$SKIP_COUNT" "$EXIT_CODE"
    printf '}\n'
else
    printf '\n摘要: OK=%d WARN=%d FAIL=%d SKIP=%d\n' \
        "$OK_COUNT" "$WARN_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"
    if [ "$FAIL_COUNT" -gt 0 ]; then
        printf '结果: 存在必需项 FAIL，请按上面的建议修复后重试。\n'
    else
        printf '结果: 未发现必需项缺失。\n'
    fi
fi

exit "$EXIT_CODE"
