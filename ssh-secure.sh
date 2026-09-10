#!/usr/bin/env bash

set -e

# ==============================
# VPS SSH 安全初始化脚本
# Debian / Ubuntu
#
# SSH 端口：保持系统原配置，不修改
# SSH 公钥：仅保留指定公钥
# SSH 密码登录：强制关闭
# 不创建额外安全配置文件
# 不做任何备份
# ==============================

PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOXNVMFwZalB4LCLyqRzrgBIvcmW3+tfQmD2qQsG5K3g"

SSHD_CONFIG="/etc/ssh/sshd_config"
AUTHORIZED_KEYS="/root/.ssh/authorized_keys"
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"

echo "[1/8] 检查环境..."

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

echo "[2/8] 检查当前 SSH 端口..."

CURRENT_PORTS="$(sshd -T | awk '$1=="port" {print $2}')"

if [ -z "$CURRENT_PORTS" ]; then
    echo "错误：无法获取当前 SSH 端口。"
    exit 1
fi

echo "      当前 SSH 端口："
echo "$CURRENT_PORTS" | sed 's/^/      /'

echo "      SSH 端口保持不变。"

echo "[3/8] 配置 SSH 目录..."

mkdir -p /root/.ssh
chmod 700 /root/.ssh

echo "[4/8] 清理旧公钥..."

rm -f "$AUTHORIZED_KEYS"

printf '%s\n' "$PUBLIC_KEY" > "$AUTHORIZED_KEYS"

chmod 600 "$AUTHORIZED_KEYS"

echo "      仅保留指定公钥。"

echo "[5/8] 强制关闭 SSH 密码认证..."

# 修改主配置文件
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

# 清理 sshd_config.d 中明确开启密码认证的配置
if [ -d "$SSH_CONFIG_DIR" ]; then

    find "$SSH_CONFIG_DIR" -type f \( -name "*.conf" -o -name "*.config" \) -print0 2>/dev/null |
    while IFS= read -r -d '' file; do

        # 删除明确设置为 yes 的 PasswordAuthentication
        sed -i -E '/^[[:space:]]*PasswordAuthentication[[:space:]]+yes[[:space:]]*$/d' "$file"

        # 删除明确设置为 yes 的 KbdInteractiveAuthentication
        sed -i -E '/^[[:space:]]*KbdInteractiveAuthentication[[:space:]]+yes[[:space:]]*$/d' "$file"

        # 删除明确设置为 yes 的 ChallengeResponseAuthentication
        sed -i -E '/^[[:space:]]*ChallengeResponseAuthentication[[:space:]]+yes[[:space:]]*$/d' "$file"

    done

fi

echo "      密码认证相关配置已强制关闭。"

echo "[6/8] 检查 SSH 配置..."

sshd -t

echo "      SSH 配置检查通过。"

echo "[7/8] 验证最终生效配置..."

FINAL_PASSWORD="$(sshd -T | awk '$1=="passwordauthentication" {print $2}')"
FINAL_KBD="$(sshd -T | awk '$1=="kbdinteractiveauthentication" {print $2}')"
FINAL_ROOT="$(sshd -T | awk '$1=="permitrootlogin" {print $2}')"
FINAL_PUBKEY="$(sshd -T | awk '$1=="pubkeyauthentication" {print $2}')"

echo "      PasswordAuthentication: $FINAL_PASSWORD"
echo "      KbdInteractiveAuthentication: $FINAL_KBD"
echo "      PermitRootLogin: $FINAL_ROOT"
echo "      PubkeyAuthentication: $FINAL_PUBKEY"

if [ "$FINAL_PASSWORD" != "no" ]; then
    echo
    echo "错误：PasswordAuthentication 仍然不是 no。"
    exit 1
fi

if [ "$FINAL_KBD" != "no" ]; then
    echo
    echo "错误：KbdInteractiveAuthentication 仍然不是 no。"
    exit 1
fi

if [ "$FINAL_ROOT" != "prohibit-password" ]; then
    echo
    echo "错误：PermitRootLogin 配置异常。"
    exit 1
fi

if [ "$FINAL_PUBKEY" != "yes" ]; then
    echo
    echo "错误：PubkeyAuthentication 配置异常。"
    exit 1
fi

KEY_COUNT="$(wc -l < "$AUTHORIZED_KEYS")"

echo
echo "      authorized_keys：${KEY_COUNT} 行"

echo "[8/8] Reload SSH..."

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