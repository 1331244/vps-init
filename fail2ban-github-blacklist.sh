#!/usr/bin/env bash
set -euo pipefail

BLACKLIST_URL="${1:-${BLACKLIST_URL:-}}"
if [[ -z "$BLACKLIST_URL" ]]; then
    echo "用法: sudo $0 <GitHub raw txt URL>" >&2
    exit 2
fi
[[ "$EUID" -eq 0 ]] || { echo "请使用 root 权限运行。" >&2; exit 1; }
command -v curl >/dev/null || { echo "缺少 curl，请先安装。" >&2; exit 1; }
command -v fail2ban-client >/dev/null || { echo "缺少 fail2ban，请先安装。" >&2; exit 1; }

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
trap 'rm -f "\$tmp_file"' EXIT
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
    grep -Fxq "\$line" "\$STATE_FILE" && continue
    echo "\$line" >> "\$STATE_FILE"
    echo "\$(date -u +%FT%TZ) \$line" >> "\$LOG_FILE"
done < "\$tmp_file"
fail2ban-client reload >/dev/null
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
