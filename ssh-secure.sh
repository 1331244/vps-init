#!/usr/bin/env bash

set -e

# ==============================
# VPS SSH 安全初始化脚本
# Debian / Ubuntu
# 不修改 SSH 端口
# 不创建额外 SSH 配置文件
# 不做任何备份
# ==============================

PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOXNVMFwZalB4LCLyqRzrgBIvcmW3+tfQmD2qQsG5K3g"

SSHD_CONFIG="/etc/ssh/sshd_config"
AUTHORIZED_KEYS="/root/.ssh/authorized_keys"

echo "[1/7] 检查环境..."

if [ "$(id -u)" -ne 0 ]; then
    echo "错误：请使用 root 用户运行。"
    exit 1
fi

if [ ! -f "$SSHD_CONFIG" ]; then
    echo "错误：未找到 $SSHD_CONFIG"
    exit 1
fi

if ! command -v sshd >/dev/null 2>&1; then
    echo "错误：未找到 sshd。"
    exit 1
fi

echo "      环境检查通过。"

echo "[2/7] 配置 SSH 目录..."

mkdir -p /root/.ssh
chmod 700 /root/.ssh

echo "[3/7] 清理旧公钥..."

rm -f "$AUTHORIZED_KEYS"

printf '%s\n' "$PUBLIC_KEY" > "$AUTHORIZED_KEYS"

chmod 600 "$AUTHORIZED_KEYS"

echo "      仅保留指定公钥。"

echo "[4/7] 修改 SSH 系统配置..."

# 删除已有的认证相关配置
sed -i -E '/^[[:space:]]*#?[[:space:]]*PubkeyAuthentication[[:space:]]+/d' "$SSHD_CONFIG"
sed -i -E '/^[[:space:]]*#?[[:space:]]*PasswordAuthentication[[:space:]]+/d' "$SSHD_CONFIG"
sed -i -E '/^[[:space:]]*#?[[:space:]]*KbdInteractiveAuthentication[[:space:]]+/d' "$SSHD_CONFIG"
sed -i -E '/^[[:space:]]*#?[[:space:]]*ChallengeResponseAuthentication[[:space:]]+/d' "$SSHD_CONFIG"
sed -i -E '/^[[:space:]]*#?[[:space:]]*PermitRootLogin[[:space:]]+/d' "$SSHD_CONFIG"

cat >> "$SSHD_CONFIG" <<'EOF'

# VPS SSH Security
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin prohibit-password
EOF

echo "      SSH 认证配置已更新。"
echo "      SSH 端口保持原配置不变。"

echo "[5/7] 检查 SSH 配置..."

sshd -t

echo "      SSH 配置检查通过。"

echo "[6/7] 验证 SSH 配置..."

echo "      当前 SSH 端口："

sshd -T | awk '$1=="port" {print $2}' | sed 's/^/      /'

echo
echo "      当前认证配置："

sshd -T | grep -E '^(permitrootlogin|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication)' | sed 's/^/      /'

KEY_COUNT=$(wc -l < "$AUTHORIZED_KEYS")

echo
echo "      authorized_keys：${KEY_COUNT} 行"

echo "[7/7] Reload SSH..."

if systemctl reload ssh 2>/dev/null; then
    echo "      SSH reload 成功。"
elif systemctl reload sshd 2>/dev/null; then
    echo "      SSH reload 成功。"
else
    echo "错误：SSH reload 失败。"
    exit 1
fi

echo
echo "SSH 安全配置完成。"
