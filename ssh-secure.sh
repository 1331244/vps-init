#!/usr/bin/env bash

set -u

# ============================================================
# VPS SSH 安全初始化脚本
# GitHub: https://github.com/1331244/vps-init
#
# 功能：
# 1. 更新 Root SSH 公钥
# 2. 禁止 SSH 密码登录
# 3. 禁止 SSH Keyboard-Interactive 登录
# 4. Root 仅允许公钥登录
# 5. 不修改 SSH 端口
# 6. 清理可能冲突的 SSH 配置
# 7. 检查 sshd 实际生效配置
#
# 注意：
# - 本脚本不提供备份功能
# - 会覆盖 /root/.ssh/authorized_keys
# - 请确保下面 PUBLIC_KEY 是你自己的公钥
# ============================================================

set -o pipefail

# ------------------------------------------------------------
# Root 检查
# ------------------------------------------------------------

if [[ "${EUID}" -ne 0 ]]; then
    echo "✗ 请使用 root 用户运行此脚本。"
    exit 1
fi

# ------------------------------------------------------------
# 公钥
# ------------------------------------------------------------

PUBLIC_KEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDCoRpHB5f4boQ5BF7itCCpKaRtuz2dQ8U1zXqMjL94g 888'

if [[ -z "$PUBLIC_KEY" || "$PUBLIC_KEY" == "请把你的SSH公钥放在这里" ]]; then
    echo "✗ PUBLIC_KEY 尚未配置。"
    echo "请编辑脚本中的 PUBLIC_KEY。"
    exit 1
fi

# ------------------------------------------------------------
# 基础函数
# ------------------------------------------------------------

info() {
    echo "✓ $1"
}

error() {
    echo "✗ $1"
}

warn() {
    echo "! $1"
}

# ------------------------------------------------------------
# 检查 Bash
# ------------------------------------------------------------

if [[ -z "${BASH_VERSION:-}" ]]; then
    echo "✗ 此脚本需要 Bash。"
    exit 1
fi

# ------------------------------------------------------------
# 检测系统
# ------------------------------------------------------------

OS_NAME="Unknown"

if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_NAME="${PRETTY_NAME:-${NAME:-Unknown}}"
fi

info "系统：$OS_NAME"

# ------------------------------------------------------------
# 检测 Init
# ------------------------------------------------------------

INIT_SYSTEM="unknown"

if command -v systemctl >/dev/null 2>&1; then
    INIT_SYSTEM="systemd"
elif command -v rc-service >/dev/null 2>&1; then
    INIT_SYSTEM="openrc"
fi

info "Init：$INIT_SYSTEM"

# ------------------------------------------------------------
# 检测 sshd
# ------------------------------------------------------------

SSHD_BIN=""

for bin in \
    /usr/sbin/sshd \
    /sbin/sshd \
    "$(command -v sshd 2>/dev/null || true)"
do
    if [[ -n "$bin" && -x "$bin" ]]; then
        SSHD_BIN="$bin"
        break
    fi
done

if [[ -z "$SSHD_BIN" ]]; then
    error "找不到 sshd。"
    exit 1
fi

info "sshd：$SSHD_BIN"

# ------------------------------------------------------------
# SSH 配置文件
# ------------------------------------------------------------

SSHD_CONFIG="/etc/ssh/sshd_config"

if [[ ! -f "$SSHD_CONFIG" ]]; then
    error "SSH 配置文件不存在：$SSHD_CONFIG"
    exit 1
fi

info "SSH 配置：$SSHD_CONFIG"

# ------------------------------------------------------------
# 检测 SSH 服务
# ------------------------------------------------------------

SSH_SERVICE=""

if [[ "$INIT_SYSTEM" == "systemd" ]]; then

    if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then
        SSH_SERVICE="ssh"
    elif systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
        SSH_SERVICE="sshd"
    elif systemctl status ssh >/dev/null 2>&1; then
        SSH_SERVICE="ssh"
    elif systemctl status sshd >/dev/null 2>&1; then
        SSH_SERVICE="sshd"
    fi

elif [[ "$INIT_SYSTEM" == "openrc" ]]; then

    if rc-service ssh status >/dev/null 2>&1; then
        SSH_SERVICE="ssh"
    elif rc-service sshd status >/dev/null 2>&1; then
        SSH_SERVICE="sshd"
    fi
fi

if [[ -z "$SSH_SERVICE" ]]; then
    warn "无法自动确定 SSH 服务名称。"
else
    info "SSH 服务：$SSH_SERVICE"
fi

# ------------------------------------------------------------
# 检测当前 SSH 端口
# ------------------------------------------------------------

CURRENT_PORT=""

if command -v sshd >/dev/null 2>&1; then
    CURRENT_PORT=$(
        "$SSHD_BIN" -T 2>/dev/null |
        awk '$1 == "port" {print $2; exit}'
    )
fi

if [[ -z "$CURRENT_PORT" ]]; then
    CURRENT_PORT="22"
fi

info "当前 SSH 端口：$CURRENT_PORT"
echo "  脚本不会修改 SSH 端口。"

# ------------------------------------------------------------
# 检查公钥格式
# ------------------------------------------------------------

if ! printf '%s\n' "$PUBLIC_KEY" | grep -Eq \
    '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521) [A-Za-z0-9+/=]+([[:space:]].*)?$'
then
    error "PUBLIC_KEY 格式看起来不正确。"
    exit 1
fi

# ------------------------------------------------------------
# SSH 目录
# ------------------------------------------------------------

mkdir -p /root/.ssh

chmod 700 /root/.ssh
chown root:root /root/.ssh

# ------------------------------------------------------------
# 更新 Root 公钥
# ------------------------------------------------------------

printf '%s\n' "$PUBLIC_KEY" > /root/.ssh/authorized_keys

chmod 600 /root/.ssh/authorized_keys
chown root:root /root/.ssh/authorized_keys

info "Root SSH 公钥已更新"

# ------------------------------------------------------------
# 清理主配置中的冲突项
#
# 注意：
# 不删除 Port
# 不删除 Include
# 不删除 Match
# ------------------------------------------------------------

TMP_CONFIG="$(mktemp)"

awk '
BEGIN {
    IGNORECASE=1
}

# 删除这些全局 SSH 认证配置。
# Port / Include / Match 等其他配置保持不动。

/^[[:space:]]*PasswordAuthentication[[:space:]]+/ {
    next
}

/^[[:space:]]*KbdInteractiveAuthentication[[:space:]]+/ {
    next
}

/^[[:space:]]*ChallengeResponseAuthentication[[:space:]]+/ {
    next
}

/^[[:space:]]*PubkeyAuthentication[[:space:]]+/ {
    next
}

/^[[:space:]]*PermitRootLogin[[:space:]]+/ {
    next
}

{
    print
}
' "$SSHD_CONFIG" > "$TMP_CONFIG"

cat "$TMP_CONFIG" > "$SSHD_CONFIG"
rm -f "$TMP_CONFIG"

# ------------------------------------------------------------
# 清理 sshd_config.d 中可能冲突的认证配置
# ------------------------------------------------------------

if [[ -d /etc/ssh/sshd_config.d ]]; then

    while IFS= read -r -d '' file; do

        TMP_FILE="$(mktemp)"

        awk '
        BEGIN {
            IGNORECASE=1
        }

        /^[[:space:]]*PasswordAuthentication[[:space:]]+/ {
            next
        }

        /^[[:space:]]*KbdInteractiveAuthentication[[:space:]]+/ {
            next
        }

        /^[[:space:]]*ChallengeResponseAuthentication[[:space:]]+/ {
            next
        }

        /^[[:space:]]*PubkeyAuthentication[[:space:]]+/ {
            next
        }

        /^[[:space:]]*PermitRootLogin[[:space:]]+/ {
            next
        }

        {
            print
        }
        ' "$file" > "$TMP_FILE"

        cat "$TMP_FILE" > "$file"
        rm -f "$TMP_FILE"

    done < <(find /etc/ssh/sshd_config.d \
        -maxdepth 1 \
        -type f \
        \( -name '*.conf' -o -name '*.cfg' \) \
        -print0 2>/dev/null)

fi

info "冲突 SSH 配置已清理"

# ------------------------------------------------------------
# 写入 SSH 安全配置
#
# 尽量写入主配置的 Match 之前。
# ------------------------------------------------------------

SECURITY_BLOCK='
# ============================================================
# VPS SSH Security
# ============================================================
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
'

TMP_CONFIG="$(mktemp)"

awk -v block="$SECURITY_BLOCK" '
BEGIN {
    inserted=0
}

# 在第一个 Match 之前写入全局配置
/^[[:space:]]*Match([[:space:]]|$)/ && inserted == 0 {
    printf "%s\n", block
    inserted=1
}

{
    print
}

END {
    if (inserted == 0) {
        printf "\n%s\n", block
    }
}
' "$SSHD_CONFIG" > "$TMP_CONFIG"

cat "$TMP_CONFIG" > "$SSHD_CONFIG"
rm -f "$TMP_CONFIG"

info "SSH 安全配置已写入"

# ------------------------------------------------------------
# SSH 配置语法检查
# ------------------------------------------------------------

if ! "$SSHD_BIN" -t 2>/tmp/sshd_test_error; then

    error "sshd 配置语法检查失败。"

    echo
    cat /tmp/sshd_test_error

    rm -f /tmp/sshd_test_error

    exit 1
fi

rm -f /tmp/sshd_test_error

info "sshd 配置语法检查通过"

# ------------------------------------------------------------
# 获取实际生效配置
# ------------------------------------------------------------

EFFECTIVE_CONFIG="$("$SSHD_BIN" -T 2>/dev/null)"

if [[ -z "$EFFECTIVE_CONFIG" ]]; then
    error "无法获取 sshd 实际生效配置。"
    exit 1
fi

PUBKEY_AUTH="$(printf '%s\n' "$EFFECTIVE_CONFIG" |
    awk '$1=="pubkeyauthentication" {print $2; exit}')"

PASSWORD_AUTH="$(printf '%s\n' "$EFFECTIVE_CONFIG" |
    awk '$1=="passwordauthentication" {print $2; exit}')"

KBD_AUTH="$(printf '%s\n' "$EFFECTIVE_CONFIG" |
    awk '$1=="kbdinteractiveauthentication" {print $2; exit}')"

PERMIT_ROOT="$(printf '%s\n' "$EFFECTIVE_CONFIG" |
    awk '$1=="permitrootlogin" {print $2; exit}')"

# ------------------------------------------------------------
# 显示实际配置
# ------------------------------------------------------------

echo
echo "--------------------------------------------"
echo "SSH 实际生效配置"
echo "--------------------------------------------"
printf '%-32s%s\n' "PubkeyAuthentication:" "$PUBKEY_AUTH"
printf '%-32s%s\n' "PasswordAuthentication:" "$PASSWORD_AUTH"
printf '%-32s%s\n' "KbdInteractiveAuthentication:" "$KBD_AUTH"
printf '%-32s%s\n' "PermitRootLogin:" "$PERMIT_ROOT"
echo "--------------------------------------------"

# ------------------------------------------------------------
# 验证配置
#
# Debian 13 / OpenSSH 可能返回：
#
# prohibit-password
# 或
# without-password
#
# 两者实际含义一致。
# ------------------------------------------------------------

CONFIG_OK=true

if [[ "$PUBKEY_AUTH" != "yes" ]]; then
    error "PubkeyAuthentication 未正确设置。"
    CONFIG_OK=false
fi

if [[ "$PASSWORD_AUTH" != "no" ]]; then
    error "PasswordAuthentication 未正确设置。"
    CONFIG_OK=false
fi

if [[ "$KBD_AUTH" != "no" ]]; then
    error "KbdInteractiveAuthentication 未正确设置。"
    CONFIG_OK=false
fi

if [[ "$PERMIT_ROOT" != "prohibit-password" &&
      "$PERMIT_ROOT" != "without-password" ]]; then
    error "PermitRootLogin 未正确设置。"
    CONFIG_OK=false
fi

# ------------------------------------------------------------
# 配置验证结果
# ------------------------------------------------------------

if [[ "$CONFIG_OK" != true ]]; then
    echo
    error "SSH 安全配置验证失败。"
    echo
    echo "当前实际配置："
    echo "$EFFECTIVE_CONFIG" |
        grep -Ei '^(port|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|permitrootlogin) '
    echo
    exit 1
fi

echo
info "SSH 安全配置验证通过"

# ------------------------------------------------------------
# 重新加载 SSH
# ------------------------------------------------------------

if [[ "$INIT_SYSTEM" == "systemd" && -n "$SSH_SERVICE" ]]; then

    if systemctl reload "$SSH_SERVICE" >/dev/null 2>&1; then
        info "SSH 服务已重新加载"
    else
        warn "SSH reload 失败，尝试 restart"

        if systemctl restart "$SSH_SERVICE" >/dev/null 2>&1; then
            info "SSH 服务已重新启动"
        else
            error "SSH 服务重新启动失败。"
            exit 1
        fi
    fi

elif [[ "$INIT_SYSTEM" == "openrc" && -n "$SSH_SERVICE" ]]; then

    if rc-service "$SSH_SERVICE" reload >/dev/null 2>&1; then
        info "SSH 服务已重新加载"
    else
        if rc-service "$SSH_SERVICE" restart >/dev/null 2>&1; then
            info "SSH 服务已重新启动"
        else
            error "SSH 服务重新启动失败。"
            exit 1
        fi
    fi

else
    warn "未能自动重新加载 SSH 服务。"
    warn "配置已经通过 sshd -t 检查，请手动 reload SSH。"
fi

# ------------------------------------------------------------
# 最终检查
# ------------------------------------------------------------

echo
echo "============================================"
echo "          SSH 安全配置完成"
echo "============================================"
echo
echo "SSH 端口：$CURRENT_PORT"
echo "Root 公钥：已更新"
echo "密码登录：已关闭"
echo "Keyboard-Interactive：已关闭"
echo "Root 密码登录：已关闭"
echo "Root 公钥登录：已启用"
echo
echo "PermitRootLogin 实际值：$PERMIT_ROOT"
echo
echo "注意："
echo "1. 本脚本没有修改 SSH 端口。"
echo "2. 本脚本没有创建备份。"
echo "3. /root/.ssh/authorized_keys 已被新的公钥覆盖。"
echo "4. 请确认新的 SSH 公钥登录已经可以正常使用。"
echo
echo "============================================"