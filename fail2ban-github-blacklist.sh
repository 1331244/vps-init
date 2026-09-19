#!/usr/bin/env bash
set -euo pipefail

DEFAULT_BLACKLIST_URL="https://raw.githubusercontent.com/1331244/vps-blacklist/main/blacklist.txt"
BLACKLIST_URL="${1:-${BLACKLIST_URL:-$DEFAULT_BLACKLIST_URL}}"
if [[ -z "$BLACKLIST_URL" ]]; then
    echo "用法: sudo $0 [GitHub raw txt URL]" >&2
    exit 2
fi
[[ "$EUID" -eq 0 ]] || { echo "请使用 root 权限运行。" >&2; exit 1; }
command -v curl >/dev/null || { echo "缺少 curl，请先安装。" >&2; exit 1; }
if ! command -v fail2ban-client >/dev/null 2>&1; then
    read -r -p "未检测到 Fail2Ban，是否自动安装？[y/N] " install_fail2ban
    if [[ "$install_fail2ban" =~ ^[Yy]$ ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update && apt-get install -y fail2ban
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y fail2ban
        elif command -v yum >/dev/null 2>&1; then
            yum install -y fail2ban
        elif command -v zypper >/dev/null 2>&1; then
            zypper --non-interactive install fail2ban
        elif command -v pacman >/dev/null 2>&1; then
            pacman -Sy --noconfirm fail2ban
        elif command -v apk >/dev/null 2>&1; then
            apk add --no-cache fail2ban
        else
            echo "无法识别包管理器，请手动安装 Fail2Ban。" >&2
            exit 1
        fi
    else
        echo "未安装 Fail2Ban，已取消配置。" >&2
        exit 1
    fi
fi
command -v fail2ban-client >/dev/null 2>&1 || { echo "Fail2Ban 安装失败，请手动检查。" >&2; exit 1; }

if command -v nft >/dev/null 2>&1 && [[ -f /etc/fail2ban/action.d/nftables-multiport.conf ]]; then
    BANACTION=nftables-multiport
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld && [[ -f /etc/fail2ban/action.d/firewallcmd-multiport.conf ]]; then
    BANACTION=firewallcmd-multiport
elif command -v iptables >/dev/null 2>&1 && [[ -f /etc/fail2ban/action.d/iptables-multiport.conf ]]; then
    BANACTION=iptables-multiport
elif command -v ufw >/dev/null 2>&1 && [[ -f /etc/fail2ban/action.d/ufw.conf ]]; then
    BANACTION=ufw
else
    BANACTION=
fi
BANACTION_LINE=""
[[ -n "$BANACTION" ]] && BANACTION_LINE="banaction = $BANACTION"

BASE_DIR=/var/lib/fail2ban-github-blacklist
STATE_FILE="$BASE_DIR/applied.txt"
SYNC_SCRIPT=/usr/local/sbin/fail2ban-github-blacklist-sync
LOG_FILE=/var/log/fail2ban-github-blacklist.log
install -d -m 0755 "$BASE_DIR"
touch "$STATE_FILE" "$LOG_FILE"
chmod 0600 "$STATE_FILE"

cat > "$SYNC_SCRIPT" <<SYNC
#!/usr/bin/env bash
set -euo pipefail
URL="\$BLACKLIST_URL"
STATE_FILE=/var/lib/fail2ban-github-blacklist/applied.txt
LOG_FILE=/var/log/fail2ban-github-blacklist.log
tmp_file="\$(mktemp)"
current_file="\$(mktemp)"
trap 'rm -f "\$tmp_file" "\$current_file"' EXIT
curl --fail --silent --show-error --location --max-time 30 "\$URL" -o "\$tmp_file"
while IFS= read -r line || [[ -n "\$line" ]]; do
    line="\${line%%#*}"
    line="\$(printf '%s' "\$line" | tr -d '[:space:]')"
    [[ -z "\$line" ]] && continue
    [[ "\$line" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "\$line" =~ ^[0-9A-Fa-f:]+$ ]] || continue
    if [[ "\$line" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS=. read -r a b c d <<< "\$line"
        (( a <= 255 && b <= 255 && c <= 255 && d <= 255 )) || continue
    fi
    grep -Fxq "\$line" "\$current_file" && continue
    echo "\$line" >> "\$current_file"
done < "\$tmp_file"

while IFS= read -r old_ip; do
    [[ -z "\$old_ip" ]] && continue
    if ! grep -Fxq "\$old_ip" "\$current_file"; then
        fail2ban-client set github-blacklist unbanip "\$old_ip" >/dev/null 2>&1 || true
    fi
done < "\$STATE_FILE"

while IFS= read -r line; do
    grep -Fxq "\$line" "\$STATE_FILE" && continue
    echo "\$(date -u +%FT%TZ) \$line" >> "\$LOG_FILE"
done < "\$current_file"
mv "\$current_file" "\$STATE_FILE"
SYNC
chmod 0755 "$SYNC_SCRIPT"

cat > /etc/fail2ban/filter.d/github-blacklist.conf <<'FILTER'
[Definition]
failregex = ^.* <HOST>$
ignoreregex =
FILTER
cat > /etc/fail2ban/jail.d/github-blacklist.local <<EOF
[github-blacklist]
enabled = true
filter = github-blacklist
logpath = $LOG_FILE
$BANACTION_LINE
maxretry = 1
findtime = 10m
bantime = -1
backend = auto
EOF
cat > /etc/systemd/system/fail2ban-github-blacklist.service <<EOF
[Unit]
Description=Synchronize GitHub IP blacklist into Fail2Ban
After=network-online.target fail2ban.service
[Service]
Type=oneshot
ExecStart=$SYNC_SCRIPT
EOF
cat > /etc/systemd/system/fail2ban-github-blacklist.timer <<'EOF'
[Unit]
Description=Run GitHub IP blacklist synchronization every 10 minutes
[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now fail2ban.service
systemctl enable --now fail2ban-github-blacklist.timer
systemctl start fail2ban-github-blacklist.service
echo "GitHub 黑名单同步已安装：$BLACKLIST_URL"
