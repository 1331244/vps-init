#!/usr/bin/env bash

set -Eeuo pipefail

# ============================================================
# Debian / Ubuntu VPS SSH Security Initialization
# ============================================================

PUBLIC_KEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOXNVMFwZalB4LCLyqRzrgBIvcmW3+tfQmD2qQsG5K3g'

SSH_PORT="549"

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
SSHD_DROPIN="${SSHD_DROPIN_DIR}/99-vps-security.conf"

SSH_DIR="/root/.ssh"
AUTHORIZED_KEYS="${SSH_DIR}/authorized_keys"

# ==============================
# 基础检查
# ==============================

if [ "$(id -u)" -ne 0 ]; then
    echo "错误：必须使用 root 用户执行此脚本。"
    exit 1
fi

if [ ! -f "$SSHD_CONFIG" ]; then
    echo "错误：未找到 $SSHD_CONFIG"
    exit 1
fi

if ! command -v sshd >/dev/null 2>&1; then
    echo "错误：未找到 sshd，请先安装 OpenSSH Server。"
    exit 1
fi

if ! command -v ss >/dev/null 2>&1; then
    echo "错误：未找到 ss 命令。"
    exit 1
fi

# ==============================
# 检查系统
# ==============================

if [ -r /etc/os-release ]; then
    . /etc/os-release

    case "${ID:-}" in
        debian|ubuntu)
            ;;
        *)
            echo "警告：当前系统不是 Debian / Ubuntu。"
            echo "检测到：${PRETTY_NAME:-未知系统}"
            ;;
    esac
fi

# ==============================
# 检查 SSH 端口
# ==============================

echo "[1/8] 检查 SSH 端口 ${SSH_PORT}..."

CURRENT_SSH_PORTS="$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -u || true)"

if ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:|\.)${SSH_PORT}$"; then

    if echo "$CURRENT_SSH_PORTS" | grep -qx "$SSH_PORT"; then
        echo "      SSH 已经使用端口 ${SSH_PORT}，继续。"
    else
        echo "错误：端口 ${SSH_PORT} 已被其他程序占用。"
        echo
        ss -lntp || true
        exit 1
    fi
else
    echo "      端口 ${SSH_PORT} 可用。"
fi

# ==============================
# 配置 SSH 目录
# ==============================

echo "[2/8] 配置 SSH 目录..."

mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

# ==============================
# 清理并写入公钥
# ==============================

echo "[3/8] 清理旧公钥..."

# 删除原有 authorized_keys
rm -f "$AUTHORIZED_KEYS"

# 只写入指定公钥
printf '%s\n' "$PUBLIC_KEY" > "$AUTHORIZED_KEYS"

chmod 600 "$AUTHORIZED_KEYS"

echo "      仅保留指定公钥。"

# ==============================
# 写入 SSH 安全配置
# ==============================

echo "[4/8] 写入 SSH 安全配置..."

mkdir -p "$SSHD_DROPIN_DIR"

cat > "$SSHD_DROPIN" <<EOF
# Managed by vps-init

Port ${SSH_PORT}

PubkeyAuthentication yes

PasswordAuthentication no

KbdInteractiveAuthentication no

ChallengeResponseAuthentication no

PermitRootLogin prohibit-password
EOF

chmod 644 "$SSHD_DROPIN"

# ==============================
# 检查 SSH 配置
# ==============================

echo "[5/8] 检查 SSH 配置..."

if ! sshd -t; then
    echo
    echo "错误：SSH 配置检查失败。"
    echo "正在删除本次生成的配置。"

    rm -f "$SSHD_DROPIN"

    exit 1
fi

echo "      SSH 配置检查通过。"

# ==============================
# 验证最终配置
# ==============================

echo "[6/8] 验证 SSH 配置..."

FINAL_CONFIG="$(sshd -T)"

EXPECTED_CONFIG=(
    "port ${SSH_PORT}"
    "pubkeyauthentication yes"
    "passwordauthentication no"
    "kbdinteractiveauthentication no"
)

for CONFIG in "${EXPECTED_CONFIG[@]}"; do
    if ! echo "$FINAL_CONFIG" | grep -Fxq "$CONFIG"; then
        echo "错误：未检测到预期配置：$CONFIG"
        exit 1
    fi
done

ROOT_LOGIN="$(echo "$FINAL_CONFIG" | awk '$1=="permitrootlogin"{print $2; exit}')"

case "$ROOT_LOGIN" in
    without-password|prohibit-password)
        ;;
    *)
        echo "错误：root 登录策略异常：${ROOT_LOGIN}"
        exit 1
        ;;
esac

echo "      SSH 配置验证通过。"

# ==============================
# UFW
# ==============================

echo "[7/8] 检查防火墙..."

if command -v ufw >/dev/null 2>&1; then

    UFW_STATUS="$(ufw status 2>/dev/null || true)"

    if echo "$UFW_STATUS" | grep -q "Status: active"; then

        ufw allow "${SSH_PORT}/tcp" >/dev/null

        echo "      UFW 已放行 ${SSH_PORT}/tcp。"

    else
        echo "      UFW 未启用，跳过。"
    fi

else
    echo "      未安装 UFW，跳过。"
fi

# ==============================
# Reload SSH
# ==============================

echo "[8/8] Reload SSH..."

if systemctl reload ssh 2>/dev/null; then
    echo "      SSH reload 成功。"
elif systemctl reload sshd 2>/dev/null; then
    echo "      SSH reload 成功。"
else
    echo "错误：无法 reload SSH。"
    exit 1
fi

sleep 1

# ==============================
# 最终状态
# ==============================

echo
echo "SSH 端口："
sshd -T | grep '^port '

echo
echo "认证配置："
sshd -T | grep -E '^(permitrootlogin|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication) '

echo
echo "authorized_keys："
wc -l "$AUTHORIZED_KEYS"

echo
echo "SSH 监听："
ss -lntp 2>/dev/null | grep ":${SSH_PORT}" || true

echo
echo "SSH 安全配置完成。"
