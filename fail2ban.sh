JAIL_CONF="/etc/fail2ban/jail.local"
LOG_FILE="/var/log/fail2ban.log"
TARGET_JAIL="sshd"

# 参数读取：优先读 [sshd] 段 → 读不到再读 [DEFAULT] 段
# 递增参数（bantime.increment/factor/maxtime）只应在 [DEFAULT] 段生效
get_f2b_conf() {
    local key=$1
    [ -f "$JAIL_CONF" ] || return
    # 1. 先读 [sshd] 段
    local result
    result=$(awk -v t="$TARGET_JAIL" -v k="$key" '
        BEGIN { in_block=0; result="" }
        $0 ~ "^\\[" t "\\][[:space:]]*$" { in_block=1; next }
        /^[[:space:]]*\[/ { in_block=0 }
        in_block && $0 ~ "^[[:space:]]*" k "[[:space:]]*=" {
            value=$0
            sub(/^[[:space:]]*[^=]+=[[:space:]]*/, "", value)
            sub(/[[:space:]]+$/, "", value)
            result = value
        }
        END { if (result != "") print result }
    ' "$JAIL_CONF")
    # 2. [sshd] 段没有 → 从 [DEFAULT] 段取
    if [ -z "$result" ]; then
        result=$(awk -v k="$key" '
            BEGIN { in_block=0; result="" }
            /^\[DEFAULT\][[:space:]]*$/ { in_block=1; next }
            /^[[:space:]]*\[/ { in_block=0 }
            in_block && $0 ~ "^[[:space:]]*" k "[[:space:]]*=" {
                value=$0
                sub(/^[[:space:]]*[^=]+=[[:space:]]*/, "", value)
                sub(/[[:space:]]+$/, "", value)
                result = value
            }
            END { if (result != "") print result }
        ' "$JAIL_CONF")
    fi
    echo "$result"
}

# 参数写入：
# - bantime.increment / bantime.factor / bantime.maxtime / dbfile / dbpurgeage 属于 [DEFAULT] 段
# - 其余参数写入 [sshd] 段
set_f2b_conf() {
    local key=$1 val=$2
    local target_section="$TARGET_JAIL"
    case "$key" in
        bantime.increment|bantime.factor|bantime.maxtime|dbfile|dbpurgeage)
            target_section="DEFAULT"
            ;;
    esac

    if [ ! -f "$JAIL_CONF" ]; then
        {
            echo "[DEFAULT]"
            echo "[$TARGET_JAIL]"
        } | $SUDO tee "$JAIL_CONF" > /dev/null
    fi
    # 确保目标段存在
    if ! grep -q "^\[${target_section}\]" "$JAIL_CONF"; then
        echo "" | $SUDO tee -a "$JAIL_CONF" > /dev/null
        echo "[${target_section}]" | $SUDO tee -a "$JAIL_CONF" > /dev/null
    fi

    # 判断该 key 是否已存在于目标段
    local exists
    exists=$(awk -v t="$target_section" -v k="$key" '
        BEGIN { in_block=0; found=0 }
        $0 ~ "^\\[" t "\\][[:space:]]*$" { in_block=1; next }
        /^[[:space:]]*\[/ { in_block=0 }
        in_block && $0 ~ "^[[:space:]]*" k "[[:space:]]*=" { found=1 }
        END { print found }
    ' "$JAIL_CONF")

    if [ "$exists" = "1" ]; then
        # 精确替换目标段内该 key 的值
        local tmpf; tmpf=$(mktemp)
        awk -v t="$target_section" -v k="$key" -v v="$val" '
            BEGIN { in_block=0; done=0 }
            $0 ~ "^\\[" t "\\][[:space:]]*$" { in_block=1; print; next }
            /^[[:space:]]*\[/ { in_block=0 }
            in_block && !done && $0 ~ "^[[:space:]]*" k "[[:space:]]*=" {
                print k " = " v
                done=1
                next
            }
            { print }
        ' "$JAIL_CONF" > "$tmpf"
        $SUDO cp "$tmpf" "$JAIL_CONF"
        rm -f "$tmpf"
    else
        # 追加到目标段头下方
        $SUDO sed -i "/^\[${target_section}\]/a ${key} = ${val}" "$JAIL_CONF"
    fi
}

restart_f2b() {
    echo -e "${INFO} 正在重载 Fail2Ban 配置..."
    svc_restart fail2ban
    for i in {1..5}; do
        if fail2ban-client ping >/dev/null 2>&1; then
            echo -e "${INFO} ${GREEN}成功！配置已生效。${RESET}"; return 0
        fi; sleep 1
    done
    echo -e "${ERROR} Fail2Ban 重启超时或失败。"
    echo -e "${YELLOW}请手动运行 'journalctl -u fail2ban -n 50' 排查错误。${RESET}"
}

get_fail2ban_status() {
    # 清命令缓存，否则 bash 会记住已被卸载的旧路径，
    # 导致 apt remove 后 command -v 仍返回旧路径、状态显示"已安装"。
    hash -r 2>/dev/null
    if command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client ping >/dev/null 2>&1; then
        local count
        count=$(fail2ban-client status "$TARGET_JAIL" 2>/dev/null | grep -i "Currently banned" | awk '{print $NF}')
        echo -e "${GREEN}防护中 (已封禁${count:-0} IP)${RESET}"
    elif command -v fail2ban-client >/dev/null 2>&1; then
        echo -e "${YELLOW}已安装 / 已停止${RESET}"
    else
        echo -e "${YELLOW}未安装${RESET}"
    fi
}

fmt_f2b_unit() {
    local val=$1 type=$2
    if [[ "$val" =~ ^[0-9]+$ ]]; then
        [ "$type" == "time" ] && echo "${val}秒" || { [ "$type" == "factor" ] && echo "${val}倍" || echo "$val"; }
    else echo "$val"; fi
}

validate_time() { [[ "$1" =~ ^[0-9]+[smhdw]?$ ]]; }
validate_int() { [[ "$1" =~ ^[0-9]+(\.[0-9]+)?$ ]]; }

# systemd 环境默认走 journal，不写死 logpath（避免 WARN）
# port 动态读取当前 SSH 端口，避免装 F2B 前已改端口时防护失效
# 递增参数 + 数据库配置写入 [DEFAULT] 段（Fail2Ban 官方要求）
generate_default_jail_conf() {
    local backend="auto"
    local logpath_line="logpath = ${SSH_LOG}"
    if [ "$INIT_SYS" = "systemd" ]; then
        backend="systemd"
        logpath_line=""
    fi
    local ssh_filter="sshd"
    [ "$OS_ID" = "alpine" ] && ssh_filter="alpine-sshd"
    local banaction
    banaction=$(detect_f2b_banaction 2>/dev/null) || banaction="iptables-allports"
    local current_port
    current_port=$(get_sshd_config_val "Port" "22")
    [ -z "$current_port" ] && current_port="22"
    cat <<EOF2
[DEFAULT]
backend = ${backend}
dbfile = /var/lib/fail2ban/fail2ban.sqlite3
dbpurgeage = 648000
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 7d

[${TARGET_JAIL}]
enabled = true
port = ${current_port}
filter = ${ssh_filter}
${logpath_line}
maxretry = 5
bantime = 600
findtime = 3600
banaction = ${banaction}
ignoreip = 127.0.0.1/8
EOF2
}

# 迁移：老配置里 [sshd] 段的递增参数挪到 [DEFAULT] 段
# 老版本脚本把 bantime.increment/factor/maxtime 错误地写在了 [sshd] 段
# Fail2Ban 只认 [DEFAULT]，导致"指数递增"完全不生效
# 同时确保 dbfile 和 dbpurgeage 存在（递增功能必需数据库支持）
migrate_f2b_increment() {
    [ -f "$JAIL_CONF" ] || return
    local k
    # 1. 删除 [sshd] 段内的递增参数
    for k in bantime.increment bantime.factor bantime.maxtime; do
        local sshd_has
        sshd_has=$(awk -v t="$TARGET_JAIL" -v kk="$k" '
            BEGIN { in_block=0; found=0 }
            $0 ~ "^\\[" t "\\][[:space:]]*$" { in_block=1; next }
            /^[[:space:]]*\[/ { in_block=0 }
            in_block && $0 ~ "^[[:space:]]*" kk "[[:space:]]*=" { found=1 }
            END { print found }
        ' "$JAIL_CONF")
        if [ "$sshd_has" = "1" ]; then
            $SUDO sed -i "/^\[${TARGET_JAIL}\]/,/^\[/ {/^${k}[[:space:]]*=/d}" "$JAIL_CONF"
        fi
    done

    # 2. 检查 [DEFAULT] 段是否所有必需参数齐全（递增三参数 + 数据库两参数）
    local need_fix=0
    for k in bantime.increment bantime.factor bantime.maxtime dbfile dbpurgeage; do
        local v
        v=$(awk -v kk="$k" '
            BEGIN { in_block=0; result="" }
            /^\[DEFAULT\][[:space:]]*$/ { in_block=1; next }
            /^[[:space:]]*\[/ { in_block=0 }
            in_block && $0 ~ "^[[:space:]]*" kk "[[:space:]]*=" {
                value=$0
                sub(/^[[:space:]]*[^=]+=[[:space:]]*/, "", value)
                sub(/[[:space:]]+$/, "", value)
                result = value
            }
            END { if (result != "") print result }
        ' "$JAIL_CONF")
        [ -z "$v" ] && need_fix=1
    done

    # 3. 缺失则重写 [DEFAULT] 段的全部五行配置
    if [ "$need_fix" = "1" ]; then
        # 先清理可能存在的旧配置
        for k in bantime.increment bantime.factor bantime.maxtime dbfile dbpurgeage; do
            $SUDO sed -i "/^\[DEFAULT\]/,/^\[/ {/^${k}[[:space:]]*=/d}" "$JAIL_CONF"
        done
        # 批量插入完整配置（注意顺序：数据库配置在前，递增配置在后）
        $SUDO sed -i '/^\[DEFAULT\]/a dbfile = /var/lib/fail2ban/fail2ban.sqlite3\ndbpurgeage = 648000\nbantime.increment = true\nbantime.factor = 2\nbantime.maxtime = 7d' "$JAIL_CONF"
    fi

    # 4. 确保数据库目录存在且权限正确
    if [ ! -d "/var/lib/fail2ban" ]; then
        $SUDO mkdir -p /var/lib/fail2ban
        $SUDO chmod 755 /var/lib/fail2ban
    fi
}

check_f2b_install() {
    hash -r 2>/dev/null
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        echo -e "${WARN} 未检测到 Fail2Ban 服务。"
        read -rp "是否立即安装 Fail2Ban？(y/N): " install_confirm
        [[ ! "$install_confirm" =~ ^[Yy]$ ]] && { echo -e "${WARN} 已取消安装。"; return 1; }

        echo -e "${INFO} 正在安装 Fail2Ban 及相关依赖..."
        local f2b_pkgs=()
        case "$PKG_MGR" in
            apt) f2b_pkgs=("fail2ban" "python3-systemd" "rsyslog");;
            dnf|yum) f2b_pkgs=("fail2ban" "rsyslog");;
            zypper) f2b_pkgs=("fail2ban" "rsyslog");;
            pacman) f2b_pkgs=("fail2ban");;
            apk) f2b_pkgs=("fail2ban");;
        esac

        pkg_install "${f2b_pkgs[@]}"
        hash -r 2>/dev/null

        if ! command -v fail2ban-client >/dev/null 2>&1; then
            echo -e "\n${ERROR} Fail2Ban 安装失败！${RESET}"
            check_eol_system
            echo -e "${YELLOW}请先解决软件源问题，然后重新运行本脚本。${RESET}"
            read -rp "按回车键返回..."
            return 1
        fi

        if [ ! -d "/etc/fail2ban" ]; then
            echo -e "\n${ERROR} /etc/fail2ban 目录不存在，安装可能不完整。${RESET}"
            echo -e "${YELLOW}请检查 Fail2Ban 是否安装成功：dpkg -l | grep fail2ban${RESET}"
            read -rp "按回车键返回..."
            return 1
        fi

        [ ! -f "$SSH_LOG" ] && { $SUDO touch "$SSH_LOG"; svc_enable rsyslog 2>/dev/null; svc_start rsyslog 2>/dev/null; }

        # 先生成配置文件（含递增参数 + 数据库配置），保证后续 restart 能读到完整配置
        if [ ! -f "$JAIL_CONF" ]; then
            detect_f2b_banaction >/dev/null || {
                echo -e "${ERROR} 未发现 nft 或 iptables，无法创建可工作的 SSH 封禁规则。"
                return 1
            }
            generate_default_jail_conf | $SUDO tee "$JAIL_CONF" > /dev/null
        fi

        # 确保数据库目录存在（指数递增依赖数据库持久化 IP 历史封禁次数）
        [ ! -d "/var/lib/fail2ban" ] && { $SUDO mkdir -p /var/lib/fail2ban; $SUDO chmod 755 /var/lib/fail2ban; }

        [ "$INIT_SYS" = "systemd" ] && $SUDO systemctl unmask fail2ban &>/dev/null || true
        svc_enable fail2ban
        # 关键修复：包管理器安装时可能已经自动启动 fail2ban（读的是默认 jail.conf），
        # 此时若用 svc_start 就是空操作，导致刚写入的 jail.local 不被加载。
        # 必须用 svc_restart 强制重读配置，否则指数递增不生效，直到 reboot 才行。
        if ! test_f2b_config; then
            echo -e "${ERROR} 新配置未通过测试，保持当前服务状态不变。"
            read -rp "按回车键返回..."
            return 1
        fi
        svc_restart fail2ban

        # 轮询确认服务真正就绪（首次启动可能稍慢）
        local f2b_up=0
        for i in {1..5}; do
            if fail2ban-client ping >/dev/null 2>&1; then f2b_up=1; break; fi
            sleep 1
        done
        if [ "$f2b_up" -eq 1 ]; then
            echo -e "${INFO} ${GREEN}Fail2Ban 安装并启动完成！${RESET}"
        else
            echo -e "${WARN} Fail2Ban 已安装，但服务尚未就绪，请稍后手动检查。"
        fi
        sleep 1; return 0
    fi

    # 已安装 fail2ban-client，但 /etc/fail2ban 目录缺失 = 残缺安装
    if [ ! -d "/etc/fail2ban" ]; then
        echo -e "\n${ERROR} Fail2Ban 处于残缺状态：命令存在但 /etc/fail2ban 目录缺失。${RESET}"
        echo -e "${YELLOW}可能是之前的卸载操作没有清理干净。${RESET}\n"
        echo -e "  ${GREEN}1.${RESET} 尝试修复（重新安装 Fail2Ban 以重建配置目录）"
        echo -e "  ${GREEN}2.${RESET} 强制卸载 Fail2Ban 残留"
        echo -e "  ${GREEN}0.${RESET} 返回"
        read -rp "请选择 [0-2]: " f2b_fix_opt
        case "$f2b_fix_opt" in
            1)
                echo -e "${INFO} 正在重新安装 Fail2Ban..."
                local f2b_pkgs=()
                case "$PKG_MGR" in
                    apt) f2b_pkgs=("fail2ban" "python3-systemd" "rsyslog");;
                    dnf|yum) f2b_pkgs=("fail2ban" "rsyslog");;
                    zypper) f2b_pkgs=("fail2ban" "rsyslog");;
                    pacman) f2b_pkgs=("fail2ban");;
                    apk) f2b_pkgs=("fail2ban");;
                esac
                pkg_reinstall "${f2b_pkgs[@]}"
                if [ -d "/etc/fail2ban" ]; then
                    echo -e "${INFO} ${GREEN}修复成功！${RESET}"
                    sleep 1
                else
                    echo -e "${ERROR} 修复失败，请手动处理：dpkg -l | grep fail2ban${RESET}"
                    read -rp "按回车键返回..."
                    return 1
                fi
                ;;
            2)
                echo -e "${WARN} 正在强制卸载 Fail2Ban..."
                svc_stop fail2ban 2>/dev/null
                svc_disable fail2ban 2>/dev/null
                pkg_remove fail2ban
                # 兜底：apt 失败时直接用 dpkg 清（dpkg 数据库损坏场景）
                hash -r 2>/dev/null
                if command -v fail2ban-client &>/dev/null; then
                    echo -e "${WARN} 检测到残留，尝试 dpkg 强制清除..."
                    $SUDO dpkg --purge --force-all fail2ban 2>/dev/null || true
                    $SUDO rm -f /var/lib/dpkg/info/fail2ban.* 2>/dev/null
                    hash -r 2>/dev/null
                fi
                $SUDO rm -r -- /etc/fail2ban
                $SUDO rm -f /usr/bin/fail2ban-client /usr/bin/fail2ban-server /usr/local/bin/fail2ban-* 2>/dev/null
                echo -e "${INFO} ${GREEN}Fail2Ban 已强制卸载。${RESET}"
                read -rp "按回车键返回..."
                return 1
                ;;
            *)
                return 1
                ;;
        esac
    fi

    # 记录配置修改前的哈希（md5sum 更高效，避免大文件全文对比）
    local conf_hash_before=""
    [ -f "$JAIL_CONF" ] && conf_hash_before=$(md5sum "$JAIL_CONF" 2>/dev/null | awk '{print $1}')

    if [ ! -f "$JAIL_CONF" ]; then
        detect_f2b_banaction >/dev/null || {
            echo -e "${ERROR} 未发现 nft 或 iptables，无法创建可工作的 SSH 封禁规则。"
            return 1
        }
        generate_default_jail_conf | $SUDO tee "$JAIL_CONF" > /dev/null
    else
        if ! grep -q "^\[DEFAULT\]" "$JAIL_CONF"; then
            local be="auto"; [ "$INIT_SYS" = "systemd" ] && be="systemd"
            $SUDO sed -i "1i [DEFAULT]\nbackend = ${be}" "$JAIL_CONF"
        fi
        # 迁移老配置：把 [sshd] 段错放的递增参数挪到 [DEFAULT] + 确保数据库配置存在
        migrate_f2b_increment
        if ! grep -q "^\[${TARGET_JAIL}\]" "$JAIL_CONF"; then
            detect_f2b_banaction >/dev/null || {
                echo -e "${ERROR} 未发现 nft 或 iptables，无法创建可工作的 SSH 封禁规则。"
                return 1
            }
            generate_default_jail_conf | grep -A99 "^\[${TARGET_JAIL}\]" | $SUDO tee -a "$JAIL_CONF" > /dev/null
        else
            # 保证 [sshd] 段基本参数齐全（不含递增参数，那些归 [DEFAULT]）
            local current_port
            current_port=$(get_sshd_config_val "Port" "22")
            [ -z "$current_port" ] && current_port="22"
            local defaults=(
                "enabled=true" "port=${current_port}" "filter=sshd" "maxretry=5"
                "bantime=600" "findtime=3600"
            )
            for item in "${defaults[@]}"; do
                local k="${item%%=*}" v="${item#*=}"
                [ -n "$(get_f2b_conf "$k")" ] || set_f2b_conf "$k" "$v"
            done
        fi
    fi

    # 关键修复：上面可能有迁移/补全动作改动了 jail.local，
    # 用哈希对比判断配置是否真变化，避免每次进菜单都触发 Restore Ban 刷屏。
    local conf_hash_after=""
    [ -f "$JAIL_CONF" ] && conf_hash_after=$(md5sum "$JAIL_CONF" 2>/dev/null | awk '{print $1}')

    if [ "$conf_hash_before" != "$conf_hash_after" ]; then
        # 配置有变化：重载或启动服务让新配置生效
        if fail2ban-client ping >/dev/null 2>&1; then
            restart_f2b
        else
            echo -e "${INFO} 检测到配置变更，正在启动 Fail2Ban..."
            if ! test_f2b_config; then
                echo -e "${ERROR} 配置未通过测试，未启动 Fail2Ban。"
                return 1
            fi
            svc_start fail2ban
            local f2b_up=0
            for i in {1..5}; do
                if fail2ban-client ping >/dev/null 2>&1; then f2b_up=1; break; fi
                sleep 1
            done
            if [ "$f2b_up" -eq 1 ]; then
                echo -e "${INFO} ${GREEN}Fail2Ban 已启动并加载新配置。${RESET}"
            else
                echo -e "${ERROR} Fail2Ban 启动超时或失败。"
                echo -e "${YELLOW}请手动运行 'journalctl -u fail2ban -n 50' 排查错误。${RESET}"
            fi
        fi
    else
        # 配置未变化：仅做服务状态兜底，避免每次进菜单重启导致 Restore Ban 刷屏
        if ! fail2ban-client ping >/dev/null 2>&1; then
            echo -e "${WARN} Fail2Ban 服务未运行，正在尝试启动..."
            if ! test_f2b_config; then
                echo -e "${ERROR} 配置未通过测试，未启动 Fail2Ban。"
                return 1
            fi
            svc_start fail2ban
            local f2b_up=0
            for i in {1..5}; do
                if fail2ban-client ping >/dev/null 2>&1; then f2b_up=1; break; fi
                sleep 1
            done
            if [ "$f2b_up" -eq 1 ]; then
                echo -e "${INFO} ${GREEN}Fail2Ban 已启动。${RESET}"
            else
                echo -e "${ERROR} Fail2Ban 启动超时或失败。"
                echo -e "${YELLOW}请手动运行 'journalctl -u fail2ban -n 50' 排查错误。${RESET}"
            fi
        fi
    fi

    return 0
}

uninstall_f2b() {
    echo -e "\n${RED}${BOLD}警告：即将卸载 Fail2Ban 及其配置！${RESET}"
    read -rp "确认卸载吗？(y/N): " confirm
    [[ ! "$confirm" =~ ^[Yy]$ ]] && { echo -e "${INFO} 已取消卸载。"; read -rp "按回车键继续..."; return 1; }
    svc_stop fail2ban; svc_disable fail2ban
    pkg_remove fail2ban
    # 清 bash 命令缓存：否则 command -v 仍返回已删除的旧路径，
    # 导致卸载后状态仍显示"已安装 / 已停止"。
    hash -r 2>/dev/null
    # 兜底：apt 卸载失败时用 dpkg 强制清除（dpkg 数据库损坏 / 静默失败场景）
    if command -v fail2ban-client &>/dev/null; then
        echo -e "${WARN} 检测到残留，尝试 dpkg 强制清除..."
        $SUDO dpkg --purge --force-all fail2ban 2>/dev/null || true
        $SUDO rm -f /var/lib/dpkg/info/fail2ban.* 2>/dev/null
    fi
    # 再兜底：物理删除可能的二进制残留
    $SUDO rm -f /usr/bin/fail2ban-client /usr/bin/fail2ban-server /usr/local/bin/fail2ban-* 2>/dev/null
    hash -r 2>/dev/null
    read -rp "是否同时删除配置目录 /etc/fail2ban ？(y/N): " del_conf
    [[ "$del_conf" =~ ^[Yy]$ ]] && { $SUDO rm -r -- /etc/fail2ban; echo -e "${INFO} 已删除 /etc/fail2ban"; }
    echo -e "${INFO} ${GREEN}Fail2Ban 卸载完成。${RESET}"; read -rp "按回车键继续..."
    return 0
}

change_f2b_param() {
    local name=$1 key=$2 type=$3
    local current; current=$(get_f2b_conf "$key")
    echo -e "\n${INFO} 正在修改: ${CYAN}${name}${RESET}"
    echo -e "当前值: ${GREEN}$(fmt_f2b_unit "$current" "$type")${RESET}"
    [ "$type" == "time" ] && echo -e "${GRAY}(支持后缀: s=秒, m=分, h=小时, d=天)${RESET}"
    while true; do
        read -rp "请输入新值 (留空取消): " new_val
        [ -z "$new_val" ] && return
        if [ "$type" == "time" ] && { validate_time "$new_val" || [ "$new_val" = "-1" ]; }; then break; fi
        if [ "$type" == "int" ] && validate_int "$new_val"; then break; fi
        if [ "$type" == "factor" ] && validate_int "$new_val"; then break; fi
        echo -e "${ERROR} 格式错误，请重试。"
    done
    set_f2b_conf "$key" "$new_val"; restart_f2b
}

toggle_f2b_service() {
    echo -e "\n${CYAN}------------------- 服务开关 -------------------${RESET}"
    if fail2ban-client ping >/dev/null 2>&1; then
        read -rp "是否停止并禁用 Fail2Ban? (y/N): " confirm
        [[ "$confirm" =~ ^[Yy]$ ]] && { svc_stop fail2ban; svc_disable fail2ban; echo -e "${WARN} 服务已停止。${RESET}"; }
    else
        read -rp "是否启用并启动 Fail2Ban? (y/N): " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            svc_enable fail2ban; svc_start fail2ban
            for i in {1..5}; do
                if fail2ban-client ping >/dev/null 2>&1; then echo -e "${INFO} ${GREEN}服务已成功启动。${RESET}"; read -rp "按回车键继续..."; return; fi; sleep 1
            done
            echo -e "${ERROR} 启动失败或超时。"
        fi
    fi
    read -rp "按回车键继续..."
}

unban_f2b_ip() {
    echo -e "\n${CYAN}------------------ 手动解封 IP ------------------${RESET}"
    local banned_list
    banned_list=$(fail2ban-client status "$TARGET_JAIL" 2>/dev/null | grep "Banned IP list" | awk -F':' '{print $2}' | sed 's/^[ \t]*//')
    [ -z "$banned_list" ] && banned_list="无"
    echo -e "当前被封禁列表: ${YELLOW}${banned_list}${RESET}"
    read -rp "输入要解封的 IP (留空取消): " target_ip; [ -z "$target_ip" ] && return
    $SUDO fail2ban-client set "$TARGET_JAIL" unbanip "$target_ip"
    [ $? -eq 0 ] && echo -e "${INFO} ${GREEN}解封成功: $target_ip${RESET}" || echo -e "${ERROR} 操作失败。"
    read -rp "按回车键继续..."
}

add_f2b_whitelist() {
    echo -e "\n${CYAN}------------------ 白名单管理 ------------------${RESET}"
    local current_list; current_list=$(get_f2b_conf "ignoreip")
    echo -e "当前白名单: ${YELLOW}${current_list:-继承全局或无}${RESET}"
    local current_ip; current_ip=$(echo "$SSH_CLIENT" | awk '{print $1}')
    read -rp "输入要放行的 IP (回车默认当前连接 IP: ${current_ip:-无}): " input_ip
    [ -z "$input_ip" ] && input_ip="$current_ip"
    [ -z "$input_ip" ] && echo -e "${ERROR} 无法获取 IP。" && return
    if echo "$current_list" | grep -Fq "$input_ip"; then
        echo -e "${WARN} 该 IP 已在白名单中。"
    else
        if [ -z "$current_list" ]; then set_f2b_conf "ignoreip" "$input_ip"
        else set_f2b_conf "ignoreip" "$current_list $input_ip"; fi
        restart_f2b
    fi
    read -rp "按回车键继续..."
}

view_f2b_logs() {
    clear
    echo -e "${CYAN}============================================================${RESET}"
    echo -e "${BOLD}${PURPLE}                 Fail2Ban 审计日志 (最近 20 条)${RESET}"
    echo -e "${CYAN}============================================================${RESET}"
    if [ ! -f "$LOG_FILE" ]; then
        echo -e "${WARN} 日志文件不存在: $LOG_FILE"
    else
        local out
        out=$(grep -E "(Ban|Unban)" "$LOG_FILE" 2>/dev/null | tail -n 20)
        if [ -z "$out" ]; then
            echo -e "${WARN} 暂无封禁/解封记录${RESET}"
        else
            echo "$out" | awk '{
                gsub(/Unban/, "\033[32m&\033[0m");
                gsub(/Ban/, "\033[31m&\033[0m");
                print
            }'
        fi
    fi
    echo -e "${CYAN}============================================================${RESET}"
    read -rp "按回车键返回..."
}

menu_f2b_exponential() {
    while true; do
        clear
        local inc fac max
        inc=$(get_f2b_conf "bantime.increment")
        fac=$(get_f2b_conf "bantime.factor")
        max=$(get_f2b_conf "bantime.maxtime")
        local S_INC; [ "$inc" == "true" ] && S_INC="${GREEN}启用${RESET}" || S_INC="${YELLOW}禁用${RESET}"
        echo -e "${CYAN}============================================================${RESET}"
        echo -e "${BOLD}${PURPLE}            高级: 指数封禁设置 (针对 sshd)${RESET}"
        echo -e "${CYAN}============================================================${RESET}"
        echo -e " 说明: 对重复犯错的恶意 IP，封禁时间按设定系数成倍递增"
        echo -e "${CYAN}------------------------------------------------------------${RESET}"
        echo -e "  ${GREEN}1.${RESET} 递增模式开关   [${S_INC}]"
        echo -e "  ${GREEN}2.${RESET} 增长系数       [${YELLOW}${fac:-未设置}${RESET}]$(fmt_f2b_unit "$fac" "factor")"
        echo -e "  ${GREEN}3.${RESET} 封禁上限       [${YELLOW}${max:-未设置}${RESET}]$(fmt_f2b_unit "$max" "time")"
        echo -e "${CYAN}------------------------------------------------------------${RESET}"
        echo -e "  ${GREEN}0.${RESET} 返回上级"
        echo -e "${CYAN}============================================================${RESET}"
        echo -e "${GRAY}提示: 输入对应序号后可自定义该参数${RESET}"
        read -rp "请选择 [0-3]: " sc
        case "$sc" in
            1) [ "$inc" == "true" ] && ns="false" || ns="true"; set_f2b_conf "bantime.increment" "$ns"; restart_f2b ;;
            2) change_f2b_param "增长系数 (倍数)" "bantime.factor" "factor" ;;
            3) change_f2b_param "封禁上限 (时间)" "bantime.maxtime" "time" ;;
            0) return ;;
            *) echo -e "${ERROR} 无效选项！"; sleep 1 ;;
        esac
    done
}

manage_fail2ban_menu() {
    if ! check_f2b_install; then read -rp "按回车键返回主菜单..."; return; fi
    while true; do
        clear
        VAL_MAX=$(get_f2b_conf "maxretry"); VAL_BAN=$(get_f2b_conf "bantime"); VAL_FIND=$(get_f2b_conf "findtime")
        echo -e "${CYAN}============================================================${RESET}"
        echo -e "${BOLD}${PURPLE}                     Fail2Ban 防护管理${RESET}"
        echo -e "${CYAN}============================================================${RESET}"
        echo -e "  服务状态: $(get_fail2ban_status)"
        echo -e "${CYAN}------------------------------------------------------------${RESET}"
        echo -e "  ${GREEN}1.${RESET} 最大重试次数     [${YELLOW}${VAL_MAX:-默认}${RESET}]"
        echo -e "  ${GREEN}2.${RESET} 初始封禁时长     [${YELLOW}${VAL_BAN:-默认}${RESET}]$(fmt_f2b_unit "$VAL_BAN" "time")"
        echo -e "  ${GREEN}3.${RESET} 监测时间窗口     [${YELLOW}${VAL_FIND:-默认}${RESET}]$(fmt_f2b_unit "$VAL_FIND" "time")"
        echo -e "${CYAN}------------------------------------------------------------${RESET}"
        echo -e "  ${GREEN}4.${RESET} 手动解封 IP"
        echo -e "  ${GREEN}5.${RESET} 添加 IP 白名单"
        echo -e "  ${GREEN}6.${RESET} 查看封禁日志 (最近20条)"
        echo -e "  ${GREEN}7.${RESET} 指数递增封禁设置 ->"
        echo -e "${CYAN}------------------------------------------------------------${RESET}"
        echo -e "  ${GREEN}8.${RESET} 启用 / 停止 服务"
        echo -e "  ${GREEN}9.${RESET} 卸载 Fail2Ban"
        echo -e "  ${GREEN}0.${RESET} 返回主菜单"
        echo -e "${CYAN}============================================================${RESET}"
        read -rp "请选择 [0-9]: " choice
        case "$choice" in
            1) change_f2b_param "最大重试次数" "maxretry" "int" ;;
            2) change_f2b_param "初始封禁时长" "bantime" "time" ;;
            3) change_f2b_param "监测时间窗口" "findtime" "time" ;;
            4) unban_f2b_ip ;;
            5) add_f2b_whitelist ;;
            6) view_f2b_logs ;;
            7) menu_f2b_exponential ;;
            8) toggle_f2b_service ;;
            9) # 卸载后根据返回值决定是否返回主菜单：
               #   uninstall_f2b 返回 0 = 卸载完成 → 返回主菜单
               #   uninstall_f2b 返回 1 = 用户取消 → 留在本菜单
               if uninstall_f2b; then
                   return
               fi
               ;;
            0) return ;;
            *) echo -e "${ERROR} 无效选项！"; sleep 1 ;;
        esac
    done
}

sync_f2b_ssh_port() {
    local port=$1
    [ -f "$JAIL_CONF" ] && grep -q "^\[${TARGET_JAIL}\]" "$JAIL_CONF" || return 0
    set_f2b_conf port "$port"
    if f2b_installed && fail2ban-client ping >/dev/null 2>&1; then
        echo -e "${INFO} 正在同步更新 Fail2Ban 防护端口..."
        reload_f2b_checked
    fi
}

# ============ 完整 Fail2Ban 管理扩展 ============
F2B_JAIL_DIR="/etc/fail2ban/jail.d"
F2B_FILTER_DIR="/etc/fail2ban/filter.d"
F2B_WHITELIST_FILE="/etc/fail2ban/jail.d/vps-init-whitelist.local"
F2B_MANAGED_TAG="# Managed by vps-init fail2ban.sh"

f2b_pause() { read -rp "按回车键继续..."; }
f2b_installed() { command -v fail2ban-client >/dev/null 2>&1; }
validate_ipv4() {
    local ip=$1 IFS=. octets i
    read -r -a octets <<< "$ip"
    [ "${#octets[@]}" -eq 4 ] || return 1
    for i in "${octets[@]}"; do
        [[ "$i" =~ ^[0-9]{1,3}$ ]] && [ "$((10#$i))" -le 255 ] || return 1
    done
}
validate_f2b_name() { [[ "$1" =~ ^[A-Za-z0-9_-]+$ ]]; }
validate_log_path() { [[ "$1" == /* ]] && [[ "$1" != *$'\n'* ]] && [[ "$1" != *'['* ]] && [[ "$1" != *']'* ]]; }
validate_banaction() { [[ "$1" =~ ^[A-Za-z0-9_.-]+$ ]]; }

detect_f2b_banaction() {
    if command -v nft >/dev/null 2>&1; then echo "nftables-allports"
    elif command -v iptables >/dev/null 2>&1; then echo "iptables-allports"
    else return 1
    fi
}

test_f2b_config() {
    local output
    echo -e "${INFO} 正在测试 Fail2Ban 配置..."
    output=$($SUDO fail2ban-client -t 2>&1); local rc=$?
    echo "$output"
    if [ "$rc" -ne 0 ] || ! echo "$output" | grep -qi "configuration test is successful"; then
        echo -e "${ERROR} 配置测试失败，未重载或重启服务。"
        return 1
    fi
    echo -e "${INFO} ${GREEN}配置测试成功。${RESET}"
}

reload_f2b_checked() {
    test_f2b_config || return 1
    if fail2ban-client ping >/dev/null 2>&1; then
        $SUDO fail2ban-client reload && echo -e "${INFO} ${GREEN}配置已重载。${RESET}"
    else
        echo -e "${WARN} Fail2Ban 当前未运行，配置已保存但未加载。"
    fi
}

# 覆盖旧实现：所有配置变更都先通过 fail2ban-client -t。
restart_f2b() {
    test_f2b_config || return 1
    echo -e "${INFO} 正在重启 Fail2Ban..."
    svc_restart fail2ban || { echo -e "${ERROR} 服务重启失败。"; return 1; }
    for i in {1..5}; do
        fail2ban-client ping >/dev/null 2>&1 && { echo -e "${INFO} ${GREEN}配置已生效。${RESET}"; return 0; }
        sleep 1
    done
    echo -e "${ERROR} Fail2Ban 重启后未正常运行，请查看日志。"
    return 1
}

f2b_version() { fail2ban-client --version 2>&1 | head -n 1; }
update_fail2ban() {
    f2b_installed || { echo -e "${WARN} Fail2Ban 尚未安装，请先使用安装/检查功能。"; f2b_pause; return; }
    echo -e "当前版本: ${CYAN}$(f2b_version)${RESET}"
    if [ "$PKG_MGR" != "apt" ]; then
        echo -e "${WARN} 本次更新功能仅支持 Debian/Ubuntu 的 apt。"; f2b_pause; return
    fi
    read -rp "确认使用系统包管理器更新 Fail2Ban？(y/N): " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || return
    $SUDO apt update && $SUDO apt install --only-upgrade fail2ban
    local rc=$?; hash -r 2>/dev/null
    [ "$rc" -eq 0 ] && echo -e "更新后版本: ${GREEN}$(f2b_version)${RESET}" || echo -e "${ERROR} 更新失败。"
    if fail2ban-client ping >/dev/null 2>&1; then echo -e "${INFO} ${GREEN}Fail2Ban 服务运行正常。${RESET}"
    else echo -e "${ERROR} Fail2Ban 服务未正常运行，请查看服务状态和日志。"; fi
    f2b_pause
}

list_f2b_jails() {
    fail2ban-client status 2>/dev/null | awk -F: '/Jail list/{gsub(/^[ \t]+/,"",$2); print $2}' | tr ',' ' '
}
view_f2b_jail_status() {
    f2b_installed || { echo -e "${WARN} Fail2Ban 未安装。"; f2b_pause; return; }
    local jails jail
    jails=$(list_f2b_jails); echo -e "所有 Jail: ${YELLOW}${jails:-无或服务未运行}${RESET}"
    read -rp "输入要查看的 Jail（留空仅查看总体状态）: " jail
    if [ -z "$jail" ]; then fail2ban-client status
    elif validate_f2b_name "$jail" && echo " $jails " | grep -Fq " $jail "; then fail2ban-client status "$jail"
    else echo -e "${ERROR} Jail 不存在或名称无效。"; fi
    f2b_pause
}

view_all_banned_ips() {
    local jail jails; jails=$(list_f2b_jails)
    [ -n "$jails" ] || { echo -e "${WARN} 没有可用 Jail。"; f2b_pause; return; }
    for jail in $jails; do
        echo -e "${CYAN}[$jail]${RESET}"
        fail2ban-client status "$jail" 2>/dev/null | grep -E "Currently banned|Total banned|Banned IP list"
    done
    f2b_pause
}

choose_f2b_jail() {
    local jails; jails=$(list_f2b_jails)
    echo -e "可用 Jail: ${YELLOW}${jails:-无}${RESET}" >&2
    read -rp "输入 Jail 名称（默认 sshd）: " REPLY
    REPLY=${REPLY:-sshd}
    validate_f2b_name "$REPLY" && echo " $jails " | grep -Fq " $REPLY " || return 1
    printf '%s' "$REPLY"
}

ban_f2b_ip() {
    local jail ip old_bantime current_ip
    jail=$(choose_f2b_jail) || { echo -e "${ERROR} Jail 不存在。"; f2b_pause; return; }
    read -rp "输入要永久封禁的 IPv4 地址: " ip
    validate_ipv4 "$ip" || { echo -e "${ERROR} IPv4 格式无效。"; f2b_pause; return; }
    current_ip=${SSH_CLIENT%% *}
    if [ -n "$current_ip" ] && [ "$ip" = "$current_ip" ]; then
        echo -e "${ERROR} 拒绝封禁当前 SSH 管理 IP。请先将其加入白名单。"; f2b_pause; return
    fi
    read -rp "确认在 [$jail] 永久封禁 $ip？(y/N): " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || return
    old_bantime=$(fail2ban-client get "$jail" bantime 2>/dev/null)
    $SUDO fail2ban-client set "$jail" bantime -1 >/dev/null && $SUDO fail2ban-client set "$jail" banip "$ip"
    local rc=$?
    [ -n "$old_bantime" ] && $SUDO fail2ban-client set "$jail" bantime "$old_bantime" >/dev/null 2>&1
    [ "$rc" -eq 0 ] && echo -e "${INFO} ${GREEN}已永久封禁 $ip。${RESET}" || echo -e "${ERROR} 封禁失败。"
    f2b_pause
}

unban_f2b_ip() {
    local ip jail found=0
    read -rp "输入要解封的 IPv4 地址: " ip
    validate_ipv4 "$ip" || { echo -e "${ERROR} IPv4 格式无效。"; f2b_pause; return; }
    for jail in $(list_f2b_jails); do
        if fail2ban-client status "$jail" 2>/dev/null | awk -F: '/Banned IP list/{print $2}' | grep -qwF "$ip"; then
            $SUDO fail2ban-client set "$jail" unbanip "$ip" && found=1
        fi
    done
    [ "$found" -eq 1 ] && echo -e "${INFO} ${GREEN}已从所有相关 Jail 解封 $ip。${RESET}" || echo -e "${WARN} 未发现该 IP 被封禁。"
    f2b_pause
}

whitelist_f2b_menu() {
    while true; do
        local current
        current=$(awk -F= '/^[[:space:]]*ignoreip[[:space:]]*=/{sub(/^[^=]*=[[:space:]]*/,""); print; exit}' "$F2B_WHITELIST_FILE" 2>/dev/null)
        current=${current:-127.0.0.1/8}
        echo -e "\n全局白名单（适用于所有 Jail）: ${YELLOW}${current}${RESET}\n  1. 添加 IP\n  2. 删除 IP\n  3. 查看白名单\n  0. 返回"
        read -rp "请选择 [0-3]: " opt
        case "$opt" in
            1) local ip=${SSH_CLIENT%% *}; read -rp "输入 IPv4（默认当前 SSH IP: ${ip:-无}）: " input; input=${input:-$ip}
               validate_ipv4 "$input" || { echo -e "${ERROR} IPv4 格式无效。"; continue; }
               if ! echo " $current " | grep -qwF "$input"; then
                   printf '%s\n[DEFAULT]\nignoreip = %s %s\n' "$F2B_MANAGED_TAG" "$current" "$input" | $SUDO tee "$F2B_WHITELIST_FILE" >/dev/null
               fi
               reload_f2b_checked; f2b_pause ;;
            2) read -rp "输入要删除的 IPv4: " ip; validate_ipv4 "$ip" || { echo -e "${ERROR} IPv4 格式无效。"; continue; }
               local next="" item; for item in $current; do [ "$item" = "$ip" ] || next="${next:+$next }$item"; done
               printf '%s\n[DEFAULT]\nignoreip = %s\n' "$F2B_MANAGED_TAG" "${next:-127.0.0.1/8}" | $SUDO tee "$F2B_WHITELIST_FILE" >/dev/null
               reload_f2b_checked; f2b_pause ;;
            3) f2b_pause ;;
            0) return ;;
            *) echo -e "${ERROR} 无效选项。" ;;
        esac
    done
}

ssh_f2b_menu() {
    while true; do
        echo -e "\n${BOLD}SSH 防护配置${RESET}\n  1. maxretry [$(get_f2b_conf maxretry)]\n  2. findtime [$(get_f2b_conf findtime)]\n  3. bantime [$(get_f2b_conf bantime)]\n  4. SSH Jail 开关\n  5. IP 白名单\n  6. 手动解封\n  7. 指数递增设置\n  0. 返回"
        read -rp "请选择 [0-7]: " opt
        case "$opt" in
            1) change_f2b_param "最大重试次数" maxretry int ;;
            2) change_f2b_param "监测时间窗口" findtime time ;;
            3) change_f2b_param "封禁时长" bantime time ;;
            4) local enabled; enabled=$(get_f2b_conf enabled); [ "$enabled" = true ] && enabled=false || enabled=true; set_f2b_conf enabled "$enabled"; reload_f2b_checked; f2b_pause ;;
            5) whitelist_f2b_menu ;; 6) unban_f2b_ip ;; 7) menu_f2b_exponential ;; 0) return ;;
            *) echo -e "${ERROR} 无效选项。" ;;
        esac
    done
}

custom_jail_file() { printf '%s/vps-init-%s.local' "$F2B_JAIL_DIR" "$1"; }
custom_filter_file() { printf '%s/%s.local' "$F2B_FILTER_DIR" "$1"; }
list_custom_jails() {
    local file name
    for file in "$F2B_JAIL_DIR"/vps-init-*.local; do
        [ -f "$file" ] && grep -qFx "$F2B_MANAGED_TAG" "$file" || continue
        name=${file##*/vps-init-}; echo "${name%.local}"
    done
}
read_jail_value() { awk -F= -v k="$2" '$1 ~ "^[[:space:]]*" k "[[:space:]]*$"{sub(/^[^=]*=[[:space:]]*/,""); print; exit}' "$1"; }

test_custom_rule() {
    local jail=${1:-} file filter log output
    if [ -z "$jail" ]; then
        echo -e "已有自定义 Jail: ${YELLOW}$(list_custom_jails | xargs)${RESET}"
        read -rp "输入 Jail 名称: " jail
    fi
    validate_f2b_name "$jail" || { echo -e "${ERROR} Jail 名称无效。"; return 1; }
    file=$(custom_jail_file "$jail"); [ -f "$file" ] || { echo -e "${ERROR} 找不到该自定义 Jail。"; return 1; }
    filter=$(read_jail_value "$file" filter); log=$(read_jail_value "$file" logpath)
    [ -f "$log" ] || { echo -e "${ERROR} 日志文件不存在: $log"; return 1; }
    local filter_file; filter_file=$(custom_filter_file "$filter")
    [ -f "$filter_file" ] || filter_file="$F2B_FILTER_DIR/${filter}.conf"
    [ -f "$filter_file" ] || { echo -e "${ERROR} Filter 文件不存在。"; return 1; }
    output=$($SUDO fail2ban-regex "$log" "$filter_file" 2>&1); local rc=$?
    echo "$output"
    echo -e "${CYAN}测试摘要：${RESET}"
    echo "$output" | grep -E "Lines:|matched|missed|ignored|Failregex:|Ignoreregex:" | tail -n 12
    if [ "$rc" -eq 0 ] && echo "$output" | grep -Eq "[1-9][0-9]* matched|Failregex: [1-9]"; then
        echo -e "${INFO} ${GREEN}规则测试成功且存在匹配。${RESET}"; return 0
    fi
    echo -e "${ERROR} 规则测试未通过或没有匹配日志，请检查语法、日志格式与路径。"; return 1
}

write_custom_rule() {
    local mode=$1 jail=${2:-} old_jail=$2 old_file filter log maxretry findtime bantime action regex jail_tmp filter_tmp
    [ "$mode" = edit ] && old_file=$(custom_jail_file "$old_jail")
    if [ "$mode" = create ]; then read -rp "Jail 名称: " jail
    else echo -e "正在修改 Jail: ${YELLOW}$jail${RESET}"; fi
    validate_f2b_name "$jail" && [ "$jail" != sshd ] || { echo -e "${ERROR} 名称无效或禁止操作 sshd。"; return; }
    if [ "$mode" = create ] && [ -e "$(custom_jail_file "$jail")" ]; then echo -e "${ERROR} Jail 已存在。"; return; fi
    local dfilter="" dlog="" dmax=3 dfind=1h dban=-1 daction
    if [ "$mode" = edit ]; then
        dfilter=$(read_jail_value "$old_file" filter); dlog=$(read_jail_value "$old_file" logpath)
        dmax=$(read_jail_value "$old_file" maxretry); dfind=$(read_jail_value "$old_file" findtime)
        dban=$(read_jail_value "$old_file" bantime); daction=$(read_jail_value "$old_file" banaction)
    fi
    read -rp "Filter 名称${dfilter:+ [$dfilter]}: " filter; filter=${filter:-$dfilter}
    read -rp "日志绝对路径${dlog:+ [$dlog]}: " log; log=${log:-$dlog}
    read -rp "maxretry [$dmax]: " maxretry; maxretry=${maxretry:-$dmax}
    read -rp "findtime [$dfind]: " findtime; findtime=${findtime:-$dfind}
    read -rp "bantime [$dban]（-1 为永久）: " bantime; bantime=${bantime:-$dban}
    daction=${daction:-$(detect_f2b_banaction)} || { echo -e "${ERROR} 未发现 nft 或 iptables，无法创建可工作的封禁规则。"; return; }
    read -rp "banaction（自动选择: $daction，回车接受）: " action; action=${action:-$daction}
    validate_f2b_name "$filter" && validate_log_path "$log" && [[ "$maxretry" =~ ^[1-9][0-9]*$ ]] && validate_time "$findtime" && { [ "$bantime" = -1 ] || validate_time "$bantime"; } && validate_banaction "$action" || { echo -e "${ERROR} 参数格式无效。"; return; }
    echo -e "${CYAN}请输入 failregex（必须包含 <HOST>，单行；留空保留现有 Filter）:${RESET}"
    read -r regex
    filter_tmp=$(mktemp); jail_tmp=$(mktemp)
    if [ -z "$regex" ] && [ -f "$(custom_filter_file "$dfilter")" ]; then cp "$(custom_filter_file "$dfilter")" "$filter_tmp"
    elif [[ "$regex" == *'<HOST>'* ]]; then printf '%s\n%s\n%s\n' "$F2B_MANAGED_TAG" '[Definition]' "failregex = $regex" > "$filter_tmp"
    else echo -e "${ERROR} failregex 必须包含 <HOST>。"; rm -f "$filter_tmp" "$jail_tmp"; return; fi
    printf '%s\n[%s]\nenabled = true\nfilter = %s\nlogpath = %s\nmaxretry = %s\nfindtime = %s\nbantime = %s\nbantime.increment = false\nbanaction = %s\n' "$F2B_MANAGED_TAG" "$jail" "$filter" "$log" "$maxretry" "$findtime" "$bantime" "$action" > "$jail_tmp"
    $SUDO mkdir -p "$F2B_JAIL_DIR" "$F2B_FILTER_DIR"
    $SUDO cp "$jail_tmp" "$(custom_jail_file "$jail")"; $SUDO cp "$filter_tmp" "$(custom_filter_file "$filter")"
    rm -f "$jail_tmp" "$filter_tmp"
    if ! test_custom_rule "$jail"; then echo -e "${WARN} 文件已保存，但规则测试未通过，未重载 Fail2Ban。"; return; fi
    reload_f2b_checked
}

edit_custom_rule() { local jail; echo -e "自定义 Jail: ${YELLOW}$(list_custom_jails | xargs)${RESET}"; read -rp "输入要修改的 Jail: " jail; [ -f "$(custom_jail_file "$jail")" ] && write_custom_rule edit "$jail" || echo -e "${ERROR} Jail 不存在。"; }
delete_custom_rule() {
    local jail file filter filter_file refs
    echo -e "自定义 Jail: ${YELLOW}$(list_custom_jails | xargs)${RESET}"; read -rp "输入要删除的 Jail: " jail
    validate_f2b_name "$jail" && [ "$jail" != sshd ] || { echo -e "${ERROR} 名称无效。"; return; }
    file=$(custom_jail_file "$jail"); [ -f "$file" ] && grep -qFx "$F2B_MANAGED_TAG" "$file" || { echo -e "${ERROR} 不是本脚本管理的 Jail，拒绝删除。"; return; }
    filter=$(read_jail_value "$file" filter); filter_file=$(custom_filter_file "$filter")
    echo -e "将删除 Jail: ${RED}$jail${RESET}\n配置: $file\nFilter: $filter_file"
    read -rp "确认删除？(y/N): " confirm; [[ "$confirm" =~ ^[Yy]$ ]] || return
    $SUDO rm -f -- "$file"
    refs=$(grep -RslE "^[[:space:]]*filter[[:space:]]*=[[:space:]]*${filter}[[:space:]]*$" "$F2B_JAIL_DIR" 2>/dev/null | wc -l)
    if [ "$refs" -eq 0 ] && [ -f "$filter_file" ] && grep -qFx "$F2B_MANAGED_TAG" "$filter_file"; then $SUDO rm -f -- "$filter_file"; fi
    reload_f2b_checked
}
view_custom_rules() { local jail file; for jail in $(list_custom_jails); do file=$(custom_jail_file "$jail"); echo -e "\n${CYAN}--- $jail ---${RESET}"; $SUDO sed -n '1,120p' "$file"; done; f2b_pause; }
custom_rules_menu() {
    while true; do
        echo -e "\n${BOLD}自定义规则管理${RESET}\n  1. 创建自定义规则\n  2. 修改自定义规则\n  3. 删除自定义规则\n  4. 测试规则\n  5. 查看规则\n  0. 返回"
        read -rp "请选择 [0-5]: " opt
        case "$opt" in 1) write_custom_rule create ;; 2) edit_custom_rule ;; 3) delete_custom_rule ;; 4) test_custom_rule; f2b_pause ;; 5) view_custom_rules ;; 0) return ;; *) echo -e "${ERROR} 无效选项。";; esac
    done
}

f2b_logs_menu() {
    while true; do
        echo -e "\n1. 查看最近日志\n2. 查看最近错误\n3. 查看传统日志\n0. 返回"
        read -rp "请选择 [0-3]: " opt
        case "$opt" in
            1) if command -v journalctl >/dev/null; then $SUDO journalctl -u fail2ban -n 80 --no-pager; elif [ -f "$LOG_FILE" ]; then tail -n 80 "$LOG_FILE"; fi; f2b_pause ;;
            2) if command -v journalctl >/dev/null; then $SUDO journalctl -u fail2ban -p err -n 80 --no-pager; elif [ -f "$LOG_FILE" ]; then grep -Ei 'error|fail|fatal' "$LOG_FILE" | tail -n 80; fi; f2b_pause ;;
            3) [ -f "$LOG_FILE" ] && tail -n 80 "$LOG_FILE" || echo -e "${WARN} $LOG_FILE 不存在。"; f2b_pause ;;
            0) return ;; *) echo -e "${ERROR} 无效选项。" ;;
        esac
    done
}

f2b_service_menu() {
    while true; do
        echo -e "\n1. 启动\n2. 停止\n3. 重启\n4. 查看状态\n5. 设置开机启动\n6. 取消开机启动\n0. 返回"
        read -rp "请选择 [0-6]: " opt
        case "$opt" in
            1) test_f2b_config && $SUDO systemctl start fail2ban ;;
            2) $SUDO systemctl stop fail2ban ;;
            3) restart_f2b ;;
            4) $SUDO systemctl status fail2ban --no-pager ;;
            5) $SUDO systemctl enable fail2ban ;;
            6) $SUDO systemctl disable fail2ban ;;
            0) return ;; *) echo -e "${ERROR} 无效选项。"; continue ;;
        esac
        f2b_pause
    done
}

f2b_install_menu() {
    while true; do
        echo -e "\n1. 安装 / 检查 Fail2Ban\n2. 卸载 Fail2Ban\n0. 返回"
        read -rp "请选择 [0-2]: " opt
        case "$opt" in
            1) check_f2b_install; f2b_pause ;;
            2) uninstall_f2b && return ;;
            0) return ;; *) echo -e "${ERROR} 无效选项。" ;;
        esac
    done
}

# 完整管理入口；保留旧函数供 SSH 端口同步和状态面板调用。
manage_fail2ban_menu() {
    while true; do
        clear
        echo -e "${CYAN}============================================================${RESET}"
        echo -e "${BOLD}${PURPLE}                     Fail2Ban 管理${RESET}"
        echo -e "${CYAN}============================================================${RESET}"
        echo -e "  服务状态: $(get_fail2ban_status)"
        echo -e "  ${GREEN}1.${RESET} 安装 / 检查 Fail2Ban"
        echo -e "  ${GREEN}2.${RESET} SSH 防护配置"
        echo -e "  ${GREEN}3.${RESET} 自定义规则管理"
        echo -e "  ${GREEN}4.${RESET} 查看 Jail 状态"
        echo -e "  ${GREEN}5.${RESET} 查看当前封禁 IP"
        echo -e "  ${GREEN}6.${RESET} 手动封禁 IP"
        echo -e "  ${GREEN}7.${RESET} 手动解封 IP"
        echo -e "  ${GREEN}8.${RESET} IP 白名单"
        echo -e "  ${GREEN}9.${RESET} 更新 Fail2Ban"
        echo -e "  ${GREEN}10.${RESET} 查看 Fail2Ban 日志"
        echo -e "  ${GREEN}11.${RESET} 服务管理"
        echo -e "  ${GREEN}0.${RESET} 返回"
        echo -e "${CYAN}============================================================${RESET}"
        read -rp "请选择 [0-11]: " choice
        case "$choice" in
            1) f2b_install_menu ;;
            2) f2b_installed && ssh_f2b_menu || { echo -e "${WARN} 请先安装 Fail2Ban。"; f2b_pause; } ;;
            3) f2b_installed && custom_rules_menu || { echo -e "${WARN} 请先安装 Fail2Ban。"; f2b_pause; } ;;
            4) view_f2b_jail_status ;; 5) view_all_banned_ips ;; 6) ban_f2b_ip ;; 7) unban_f2b_ip ;;
            8) f2b_installed && whitelist_f2b_menu || { echo -e "${WARN} 请先安装 Fail2Ban。"; f2b_pause; } ;;
            9) update_fail2ban ;; 10) f2b_logs_menu ;; 11) f2b_service_menu ;; 0) return ;;
            *) echo -e "${ERROR} 无效选项。"; sleep 1 ;;
        esac
    done
}
