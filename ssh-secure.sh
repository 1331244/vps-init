#!/usr/bin/env bash
# ============================================================
# 通用 Linux VPS SSH 安全配置脚本
#
# 支持：
# Debian / Ubuntu
# CentOS Stream / RHEL
# Rocky Linux / AlmaLinux
# Fedora
# Arch Linux
# openSUSE
# Alpine Linux
#
# 功能：
# - 自动识别系统
# - 自动识别 sshd
# - 自动识别 SSH 服务
# - 更新 Root SSH 公钥
# - 禁止密码登录
# - 禁止键盘交互认证
# - Root 仅允许公钥登录
# - 不修改 SSH 端口
# - 支持重复执行
# - 支持更换 SSH 公钥
# - 不创建任何备份文件
# ============================================================
set -u
set -o pipefail
# ============================================================
# 你的 SSH 公钥
#
# 修改这里为你自己的 id_ed25519.pub 完整内容
# ============================================================
PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDCoRpHB5f4boQ5BF7itCCpKaRtuz2dQ8U1zXqMjL94g 888"
# ============================================================
# 基础变量
# ============================================================
SSHD_BIN=""
SSHD_CONFIG=""
SSH_SERVICE=""
INIT_SYSTEM=""
AUTHORIZED_KEYS="/root/.ssh/authorized_keys"
# ============================================================
# 输出函数
# ============================================================
ok() {
    printf '\033[32m✓\033[0m %s\n' "$1"
}
warn() {
    printf '\033[33m!\033[0m %s\n' "$1"
}
error() {
    printf '\033[31m✗\033[0m %s\n' "$1"
}
info() {
    printf '  %s\n' "$1"
}
die() {
    error "$1"
    exit 1
}
# ============================================================
# Root 检查
# ============================================================
if [ "$(id -u)" -ne 0 ]; then
    die "请使用 root 用户运行此脚本。"
fi
# ============================================================
# 检查公钥
# ============================================================
if [ -z "$PUBLIC_KEY" ]; then
    die "PUBLIC_KEY 为空。"
fi
case "$PUBLIC_KEY" in
    ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-*\ *)
        ;;
    *)
        die "PUBLIC_KEY 格式看起来不正确。"
        ;;
esac
# ============================================================
# 检测系统
# ============================================================
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME="${PRETTY_NAME:-Linux}"
    OS_ID="${ID:-unknown}"
else
    OS_NAME="Unknown Linux"
    OS_ID="unknown"
fi
ok "系统：$OS_NAME"
# ============================================================
# 检测 Init 系统
# ============================================================
if command -v systemctl >/dev/null 2>&1 \
    && [ -d /run/systemd/system ]; then
    INIT_SYSTEM="systemd"
elif command -v rc-service >/dev/null 2>&1; then
    INIT_SYSTEM="openrc"
else
    INIT_SYSTEM="unknown"
fi
ok "Init：$INIT_SYSTEM"
# ============================================================
# 检测 sshd
# ============================================================
if command -v sshd >/dev/null 2>&1; then
    SSHD_BIN="$(command -v sshd)"
else
    for path in \
        /usr/sbin/sshd \
        /sbin/sshd \
        /usr/local/sbin/sshd
    do
        if [ -x "$path" ]; then
            SSHD_BIN="$path"
            break
        fi
    done
fi
if [ -z "$SSHD_BIN" ]; then
    die "没有找到 sshd。"
fi
ok "sshd：$SSHD_BIN"
# ============================================================
# 检测 SSH 配置文件
# ============================================================
for file in \
    /etc/ssh/sshd_config \
    /etc/sshd_config \
    /usr/local/etc/sshd_config
do
    if [ -f "$file" ]; then
        SSHD_CONFIG="$file"
        break
    fi
done
if [ -z "$SSHD_CONFIG" ]; then
    die "找不到 sshd_config。"
fi
ok "SSH 配置：$SSHD_CONFIG"
# ============================================================
# 检测 SSH 服务
# ============================================================
if [ "$INIT_SYSTEM" = "systemd" ]; then
    for service in ssh sshd; do
        if systemctl list-unit-files \
            --type=service 2>/dev/null |
            awk '{print $1}' |
            grep -qx "${service}.service"
        then
            SSH_SERVICE="$service"
            break
        fi
    done
fi
if [ "$INIT_SYSTEM" = "openrc" ]; then
    for service in sshd ssh; do
        if [ -f "/etc/init.d/$service" ]; then
            SSH_SERVICE="$service"
            break
        fi
    done
fi
if [ -z "$SSH_SERVICE" ]; then
    if [ -f /etc/init.d/sshd ]; then
        SSH_SERVICE="sshd"
    elif [ -f /etc/init.d/ssh ]; then
        SSH_SERVICE="ssh"
    fi
fi
if [ -n "$SSH_SERVICE" ]; then
    ok "SSH 服务：$SSH_SERVICE"
else
    warn "无法自动确定 SSH 服务名称。"
fi
# ============================================================
# 获取当前 SSH 端口
# ============================================================
CURRENT_PORTS="$(
    "$SSHD_BIN" -T 2>/dev/null |
    awk '$1=="port" {print $2}' |
    sort -n |
    uniq |
    tr '\n' ' '
)"
if [ -z "$CURRENT_PORTS" ]; then
    CURRENT_PORTS="22"
fi
ok "当前 SSH 端口：$CURRENT_PORTS"
info "脚本不会修改 SSH 端口。"
# ============================================================
# 创建 SSH 目录
# ============================================================
mkdir -p /root/.ssh
chmod 700 /root/.ssh
# ============================================================
# 更新 authorized_keys
# ============================================================
TMP_AUTHORIZED_KEYS="$(mktemp)"
printf '%s\n' "$PUBLIC_KEY" > "$TMP_AUTHORIZED_KEYS"
chmod 600 "$TMP_AUTHORIZED_KEYS"
chown root:root "$TMP_AUTHORIZED_KEYS"
mv "$TMP_AUTHORIZED_KEYS" "$AUTHORIZED_KEYS"
chmod 600 "$AUTHORIZED_KEYS"
chown root:root "$AUTHORIZED_KEYS"
ok "Root SSH 公钥已更新"
# ============================================================
# 清理 SSH 配置
# ============================================================
clean_ssh_directives() {
    local file="$1"
    [ -f "$file" ] || return 0
    sed -i -E \
        '/^[[:space:]]*#?[[:space:]]*PubkeyAuthentication[[:space:]]+/d' \
        "$file"
    sed -i -E \
        '/^[[:space:]]*#?[[:space:]]*PasswordAuthentication[[:space:]]+/d' \
        "$file"
    sed -i -E \
        '/^[[:space:]]*#?[[:space:]]*KbdInteractiveAuthentication[[:space:]]+/d' \
        "$file"
    sed -i -E \
        '/^[[:space:]]*#?[[:space:]]*ChallengeResponseAuthentication[[:space:]]+/d' \
        "$file"
    sed -i -E \
        '/^[[:space:]]*#?[[:space:]]*PermitRootLogin[[:space:]]+/d' \
        "$file"
}
# ============================================================
# 清理主配置
# ============================================================
clean_ssh_directives "$SSHD_CONFIG"
# ============================================================
# 清理 sshd_config.d
# ============================================================
if [ -d /etc/ssh/sshd_config.d ]; then
    while IFS= read -r -d '' file; do
        clean_ssh_directives "$file"
    done < <(
        find /etc/ssh/sshd_config.d \
            -type f \
            \( -name "*.conf" -o -name "*.config" \) \
            -print0 2>/dev/null
    )
fi
ok "冲突 SSH 配置已清理"
# ============================================================
# 安全配置
# ============================================================
SECURITY_CONFIG=$(cat <<'EOF'
# ============================================================
# VPS SSH Security
# Managed by ssh-secure.sh
# ============================================================
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin prohibit-password
EOF
)
# ============================================================
# 处理 Match 块
# ============================================================
if grep -Eq '^[[:space:]]*Match([[:space:]]|$)' "$SSHD_CONFIG"; then
    TMP_CONFIG="$(mktemp)"
    awk -v security="$SECURITY_CONFIG" '
        BEGIN {
            inserted=0
        }
        !inserted && $0 ~ /^[[:space:]]*Match([[:space:]]|$)/ {
            print security
            print ""
            inserted=1
        }
        {
            print
        }
        END {
            if (!inserted) {
                print security
            }
        }
    ' "$SSHD_CONFIG" > "$TMP_CONFIG"
    chmod --reference="$SSHD_CONFIG" "$TMP_CONFIG" 2>/dev/null || true
    chown --reference="$SSHD_CONFIG" "$TMP_CONFIG" 2>/dev/null || true
    mv "$TMP_CONFIG" "$SSHD_CONFIG"
else
    printf '\n%s\n' "$SECURITY_CONFIG" >> "$SSHD_CONFIG"
fi
ok "SSH 安全配置已写入"
# ============================================================
# sshd 配置检查
# ============================================================
if ! "$SSHD_BIN" -t 2>/dev/null; then
    error "sshd 配置检查失败。"
    error "没有自动恢复，因为本脚本不创建备份。"
    echo
    echo "请检查："
    echo "    $SSHD_CONFIG"
    echo
    echo "以及："
    echo "    /etc/ssh/sshd_config.d/"
    echo
    exit 1
fi
ok "sshd 配置语法检查通过"
# ============================================================
# 获取最终实际生效配置
# ============================================================
EFFECTIVE_CONFIG="$(
    "$SSHD_BIN" -T 2>/dev/null
)"
if [ -z "$EFFECTIVE_CONFIG" ]; then
    die "无法获取 sshd 实际生效配置。"
fi
# ============================================================
# 提取最终配置
# ============================================================
FINAL_PUBKEY="$(
    echo "$EFFECTIVE_CONFIG" |
    awk '$1=="pubkeyauthentication" {print $2; exit}'
)"
FINAL_PASSWORD="$(
    echo "$EFFECTIVE_CONFIG" |
    awk '$1=="passwordauthentication" {print $2; exit}'
)"
FINAL_KBD="$(
    echo "$EFFECTIVE_CONFIG" |
    awk '$1=="kbdinteractiveauthentication" {print $2; exit}'
)"
FINAL_ROOT="$(
    echo "$EFFECTIVE_CONFIG" |
    awk '$1=="permitrootlogin" {print $2; exit}'
)"
# ============================================================
# 显示实际配置
# ============================================================
echo
echo "--------------------------------------------"
echo "SSH 实际生效配置"
echo "--------------------------------------------"
echo "PubkeyAuthentication:          $FINAL_PUBKEY"
echo "PasswordAuthentication:       $FINAL_PASSWORD"
echo "KbdInteractiveAuthentication: $FINAL_KBD"
echo "PermitRootLogin:              $FINAL_ROOT"
echo "--------------------------------------------"
echo
# ============================================================
# 验证
# ============================================================
if [ "$FINAL_PUBKEY" != "yes" ]; then
    die "PubkeyAuthentication 未正确生效。"
fi
if [ "$FINAL_PASSWORD" != "no" ]; then
    die "PasswordAuthentication 未正确关闭。"
fi
if [ "$FINAL_KBD" != "no" ]; then
    die "KbdInteractiveAuthentication 未正确关闭。"
fi
if [ "$FINAL_ROOT" != "prohibit-password" ]; then
    die "PermitRootLogin 未正确设置。"
fi
ok "SSH 实际生效配置验证通过"
# ============================================================
# 验证 authorized_keys
# ============================================================
if [ ! -s "$AUTHORIZED_KEYS" ]; then
    die "authorized_keys 为空。"
fi
if ! grep -Fqx "$PUBLIC_KEY" "$AUTHORIZED_KEYS"; then
    die "authorized_keys 中没有找到当前公钥。"
fi
ok "当前公钥已确认写入 authorized_keys"
# ============================================================
# Reload SSH
# ============================================================
reload_ssh() {
    # systemd
    if [ "$INIT_SYSTEM" = "systemd" ] \
        && [ -n "$SSH_SERVICE" ]; then
        if systemctl reload "$SSH_SERVICE" 2>/dev/null; then
            ok "SSH reload 成功"
            return 0
        fi
        if systemctl restart "$SSH_SERVICE" 2>/dev/null; then
            ok "SSH restart 成功"
            return 0
        fi
    fi
    # OpenRC
    if [ "$INIT_SYSTEM" = "openrc" ] \
        && [ -n "$SSH_SERVICE" ]; then
        if rc-service "$SSH_SERVICE" reload 2>/dev/null; then
            ok "SSH reload 成功"
            return 0
        fi
        if rc-service "$SSH_SERVICE" restart 2>/dev/null; then
            ok "SSH restart 成功"
            return 0
        fi
    fi
    # service
    if command -v service >/dev/null 2>&1 \
        && [ -n "$SSH_SERVICE" ]; then
        if service "$SSH_SERVICE" reload 2>/dev/null; then
            ok "SSH reload 成功"
            return 0
        fi
        if service "$SSH_SERVICE" restart 2>/dev/null; then
            ok "SSH restart 成功"
            return 0
        fi
    fi
    return 1
}
# ============================================================
# 执行 Reload
# ============================================================
if [ -n "$SSH_SERVICE" ]; then
    if ! reload_ssh; then
        warn "SSH 配置有效，但无法自动 reload/restart SSH。"
        warn "请手动检查 SSH 服务。"
    fi
else
    warn "没有检测到 SSH 服务名称。"
    warn "SSH 配置已经通过 sshd 检查。"
fi
# ============================================================
# 完成
# ============================================================
echo
echo "============================================"
echo " SSH 安全配置完成"
echo "============================================"
echo
echo "系统：$OS_NAME"
echo "SSH 配置：$SSHD_CONFIG"
echo "SSH 服务：${SSH_SERVICE:-未知}"
echo "SSH 端口：$CURRENT_PORTS"
echo
echo "公钥认证：已开启"
echo "密码登录：已关闭"
echo "键盘交互：已关闭"
echo "Root：仅允许公钥"
echo
echo "============================================"
echo
echo "请确认新私钥可以正常登录后，"
echo "再关闭当前 SSH 会话。"
echo