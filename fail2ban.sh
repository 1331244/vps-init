#!/usr/bin/env bash

# 本文件通常由 init.ssh source；直接执行时转交给同目录主脚本。
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    F2B_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    if [ -x "${F2B_SCRIPT_DIR}/init.ssh" ]; then
        exec "${F2B_SCRIPT_DIR}/init.ssh" "$@"
    fi
    echo "无法找到可执行主脚本: ${F2B_SCRIPT_DIR}/init.ssh" >&2
    exit 1
fi

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
                remove_f2b_package_preserve_config
                # 兜底：apt 失败时直接用 dpkg 清（dpkg 数据库损坏场景）
                hash -r 2>/dev/null
                if command -v fail2ban-client &>/dev/null; then
                    echo -e "${WARN} 检测到残留，尝试 dpkg 强制清除..."
                    $SUDO dpkg --purge --force-all fail2ban 2>/dev/null || true
                    $SUDO rm -f /var/lib/dpkg/info/fail2ban.* 2>/dev/null
                    hash -r 2>/dev/null
                fi
                $SUDO rm -f /usr/bin/fail2ban-client /usr/bin/fail2ban-server /usr/local/bin/fail2ban-* 2>/dev/null
                echo -e "${INFO} ${GREEN}Fail2Ban 已强制卸载，/etc/fail2ban 配置已保留。${RESET}"
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

remove_f2b_package_preserve_config() {
    case "$PKG_MGR" in
        apt) $SUDO apt-get remove -y fail2ban ;;
        *) pkg_remove fail2ban ;;
    esac
}

uninstall_f2b() {
    echo -e "\n${RED}${BOLD}警告：即将卸载 Fail2Ban 及其配置！${RESET}"
    read -rp "确认卸载吗？(y/N): " confirm
    [[ ! "$confirm" =~ ^[Yy]$ ]] && { echo -e "${INFO} 已取消卸载。"; read -rp "按回车键继续..."; return 1; }
    svc_stop fail2ban; svc_disable fail2ban
    remove_f2b_package_preserve_config
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
    echo -e "${INFO} ${GREEN}Fail2Ban 卸载完成，/etc/fail2ban 配置已保留。${RESET}"; read -rp "按回车键继续..."
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

menu_f2b_exponential() {
    while true; do
        f2b_clear
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

sync_f2b_ssh_port() {
    local port=$1
    [ -f "$JAIL_CONF" ] && grep -q "^\[${TARGET_JAIL}\]" "$JAIL_CONF" || return 0
    set_f2b_conf port "$port"
    if f2b_installed; then
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
f2b_clear() {
    # 直接发送 ANSI 控制序列，兼容 TERM 未设置或系统没有 clear 命令的 SSH 会话。
    printf '\033[H\033[2J\033[3J'
}
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
    if command -v nft >/dev/null 2>&1 && f2b_action_exists "nftables-allports"; then echo "nftables-allports"
    elif command -v iptables >/dev/null 2>&1 && f2b_action_exists "iptables-allports"; then echo "iptables-allports"
    else return 1
    fi
}

f2b_action_exists() {
    [ -f "/etc/fail2ban/action.d/$1.conf" ] || [ -f "/etc/fail2ban/action.d/$1.local" ]
}

test_f2b_config() {
    local output
    echo -e "${INFO} 正在测试 Fail2Ban 配置..."
    output=$($SUDO fail2ban-client -t 2>&1); local rc=$?
    echo "$output"
    if [ "$rc" -ne 0 ]; then
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
    # 将 fail2ban-client 的状态字段汉化，数值、Jail 名称和 IP 原样保留。
    local status_output
    if [ -z "$jail" ]; then
        status_output=$(fail2ban-client status)
    elif validate_f2b_name "$jail" && echo " $jails " | grep -Fq " $jail "; then
        status_output=$(fail2ban-client status "$jail")
    else echo -e "${ERROR} Jail 不存在或名称无效。"; fi
    if [ -n "${status_output:-}" ]; then
        echo "$status_output" | sed \
            -e 's/^Status for the jail:/Jail 状态：/' \
            -e 's/^Number of jail:/Jail 数量：/' \
            -e 's/^Jail list:/Jail 列表：/' \
            -e 's/Currently failed:/当前失败次数：/' \
            -e 's/Total failed:/累计失败次数：/' \
            -e 's/Journal matches:/Journal 匹配：/' \
            -e 's/Currently banned:/当前封禁数量：/' \
            -e 's/Total banned:/累计封禁数量：/' \
            -e 's/Banned IP list:/封禁 IP 列表：/' \
            -e 's/Actions/动作/' \
            -e 's/Filter/过滤器/'
    fi
    f2b_pause
}

view_all_banned_ips() {
    local jail jails status banned_line ip index current_banned total_banned
    jails=$(list_f2b_jails)
    [ -n "$jails" ] || { echo -e "${WARN} 没有可用 Jail。"; f2b_pause; return; }
    for jail in $jails; do
        if [ "$jail" = "manual-ban" ]; then
            echo -e "\n${CYAN}[$jail]（手动封禁）${RESET}"
        else
            echo -e "\n${CYAN}[$jail]${RESET}"
        fi
        status=$(fail2ban-client status "$jail" 2>/dev/null)
        current_banned=$(echo "$status" | awk -F: '/Currently banned/{gsub(/[[:space:]]/,"",$2); print $2}')
        total_banned=$(echo "$status" | awk -F: '/Total banned/{gsub(/[[:space:]]/,"",$2); print $2}')
        echo "当前封禁数量: ${current_banned:-0}"
        echo "累计封禁数量: ${total_banned:-0}"
        banned_line=$(echo "$status" | awk -F: '/Banned IP list/{sub(/^[[:space:]]*/,"",$2); print $2}')
        if [ -n "$banned_line" ]; then
            echo -e "封禁 IP 列表:"
            index=1
            for ip in $banned_line; do
                printf '  %2d. %s\n' "$index" "$ip"
                index=$((index + 1))
            done
        else
            if [ "${total_banned:-0}" -gt 0 ]; then
                echo "当前没有封禁 IP（历史累计 ${total_banned} 次）"
            else
                echo "当前没有封禁 IP"
            fi
        fi
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
        echo -e "${ERROR} 为防止 SSH 断连，拒绝封禁当前管理 IP。"; f2b_pause; return
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

get_f2b_whitelist() {
    local managed ssh_list
    managed=$(awk -F= '/^[[:space:]]*ignoreip[[:space:]]*=/{sub(/^[^=]*=[[:space:]]*/,""); print; exit}' "$F2B_WHITELIST_FILE" 2>/dev/null)
    if [ -n "$managed" ]; then
        printf '%s\n' "127.0.0.1/8 $managed"
    else
        ssh_list=$(get_f2b_conf ignoreip)
        printf '%s\n' "127.0.0.1/8 $ssh_list"
    fi | awk '{for(i=1;i<=NF;i++) if(!seen[$i]++) printf "%s%s", sep, $i; sep=" "} END{print ""}'
}

write_f2b_whitelist() {
    local list=$1 tmp backup="" jail rc
    tmp=$(mktemp)
    {
        echo "$F2B_MANAGED_TAG"
        echo "[DEFAULT]"
        echo "ignoreip = $list"
        echo ""
        # sshd 的旧配置可能有 Jail 级 ignoreip，必须显式覆盖才能让白名单生效。
        echo "[$TARGET_JAIL]"
        echo "ignoreip = $list"
        for jail in $(list_custom_jails); do
            echo ""
            echo "[$jail]"
            echo "ignoreip = $list"
        done
    } > "$tmp"
    if [ -f "$F2B_WHITELIST_FILE" ]; then
        backup=$(mktemp); $SUDO cp "$F2B_WHITELIST_FILE" "$backup"
    fi
    $SUDO mkdir -p "$F2B_JAIL_DIR"
    $SUDO cp "$tmp" "$F2B_WHITELIST_FILE"; rm -f "$tmp"
    if ! test_f2b_config; then
        if [ -n "$backup" ]; then $SUDO cp "$backup" "$F2B_WHITELIST_FILE"
        else $SUDO rm -f -- "$F2B_WHITELIST_FILE"; fi
        rm -f "$backup"
        echo -e "${ERROR} 白名单配置已回滚。"
        return 1
    fi
    rm -f "$backup"
    if fail2ban-client ping >/dev/null 2>&1; then
        $SUDO fail2ban-client reload && echo -e "${INFO} ${GREEN}白名单已生效。${RESET}"
    else
        echo -e "${WARN} 配置测试通过；服务未运行，将在下次启动时生效。"
    fi
}

whitelist_f2b_menu() {
    while true; do
        f2b_clear
        local current; current=$(get_f2b_whitelist)
        echo -e "\n全局白名单（适用于所有 Jail）: ${YELLOW}${current}${RESET}\n  1. 添加 IP\n  2. 删除 IP\n  3. 查看白名单\n  0. 返回"
        read -rp "请选择 [0-3]: " opt
        case "$opt" in
            1) local ip=${SSH_CLIENT%% *}; read -rp "输入 IPv4（默认当前 SSH IP: ${ip:-无}）: " input; input=${input:-$ip}
               validate_ipv4 "$input" || { echo -e "${ERROR} IPv4 格式无效。"; continue; }
               if ! echo " $current " | grep -qwF "$input"; then
                   write_f2b_whitelist "$current $input"
               fi
               f2b_pause ;;
            2) read -rp "输入要删除的 IPv4: " ip; validate_ipv4 "$ip" || { echo -e "${ERROR} IPv4 格式无效。"; continue; }
               if [ -n "${SSH_CLIENT%% *}" ] && [ "$ip" = "${SSH_CLIENT%% *}" ]; then
                   echo -e "${ERROR} 拒绝删除当前 SSH 管理 IP 的白名单，以免当前会话被自动封禁。"; f2b_pause; continue
               fi
               local next="" item; for item in $current; do [ "$item" = "$ip" ] || next="${next:+$next }$item"; done
               write_f2b_whitelist "${next:-127.0.0.1/8}"; f2b_pause ;;
            3) f2b_pause ;;
            0) return ;;
            *) echo -e "${ERROR} 无效选项。" ;;
        esac
    done
}

ssh_f2b_menu() {
    while true; do
        f2b_clear
        echo -e "\n${BOLD}SSH 防护配置${RESET}\n  1. 最大重试次数 [$(get_f2b_conf maxretry)]\n  2. 检测时间窗口 [$(get_f2b_conf findtime)]\n  3. 封禁时长 [$(get_f2b_conf bantime)]\n  4. SSH 防护开关\n  5. IP 白名单\n  6. 手动解封\n  7. 递增封禁设置\n  0. 返回"
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
# Fail2Ban 的 filter.d 默认只扫描 *.conf；使用 .local 会导致规则文件
# 虽然写入成功、fail2ban-regex 也能测试通过，但服务实际加载不到。
# 自定义 Filter 统一使用 .conf（Jail 仍可使用 .local）。
custom_filter_file() { printf '%s/%s.conf' "$F2B_FILTER_DIR" "$1"; }
custom_filter_existing() {
    local name=$1
    if [ -f "$(custom_filter_file "$name")" ]; then
        custom_filter_file "$name"
    elif [ -f "$F2B_FILTER_DIR/${name}.local" ]; then
        printf '%s/%s.local' "$F2B_FILTER_DIR" "$name"
    else
        custom_filter_file "$name"
    fi
}
find_custom_jail_file() {
    local jail=$1 file
    file=$(custom_jail_file "$jail")
    [ -f "$file" ] && { printf '%s\n' "$file"; return 0; }
    for file in "$F2B_JAIL_DIR"/*.local "$F2B_JAIL_DIR"/*.conf; do
        [ -f "$file" ] || continue
        awk -v s="$jail" '$0 ~ "^\\[" s "\\][[:space:]]*$" {found=1; exit} END {exit !found}' "$file" \
            && { printf '%s\n' "$file"; return 0; }
    done
    return 1
}
list_custom_jails() {
    local file name section enabled
    [ -d "$F2B_JAIL_DIR" ] || return 0
    # 同时显示脚本创建的 Jail 和用户手动放入 jail.d 的自定义配置。
    # whitelist 文件不是 Jail，且仅显示包含实际段落的配置，避免把目录中的
    # 注释/备份文件误认为规则。
    for file in "$F2B_JAIL_DIR"/*.local "$F2B_JAIL_DIR"/*.conf; do
        [ -f "$file" ] || continue
        [ "${file##*/}" = "vps-init-whitelist.local" ] && continue
        while IFS= read -r section; do
            name=${section#\[}; name=${name%\]}
            # sshd 是安装时的内置 Jail，不属于自定义规则管理范围。
            [ "$name" = DEFAULT ] || [ "$name" = sshd ] && continue
            enabled=$(awk -v s="$name" '
                $0 ~ "^\\[" s "\\][[:space:]]*$" {inside=1; next}
                /^[[:space:]]*\[/ {inside=0}
                inside && /^[[:space:]]*enabled[[:space:]]*=/ {v=$0; sub(/^[^=]*=[[:space:]]*/,"",v); print v; exit}
            ' "$file")
            [ "$enabled" = true ] || grep -qFx "$F2B_MANAGED_TAG" "$file" || continue
            echo "$name"
        done < <(sed -nE 's/^\[([^]]+)\][[:space:]]*$/[\1]/p' "$file")
    done | sort -u
}
read_jail_value() { awk -F= -v k="$2" '$1 ~ "^[[:space:]]*" k "[[:space:]]*$"{sub(/^[^=]*=[[:space:]]*/,""); print; exit}' "$1"; }

run_f2b_regex() {
    local log=$1 filter_file=$2 output rc lines matched missed ignored
    output=$($SUDO fail2ban-regex "$log" "$filter_file" 2>&1); rc=$?
    lines=$(echo "$output" | sed -nE 's/^[[:space:]]*Lines:[[:space:]]*([0-9]+).*/\1/p' | head -n 1)
    matched=$(echo "$output" | sed -nE 's/.*[^0-9]([0-9]+)[[:space:]]+matched.*/\1/p' | head -n 1)
    missed=$(echo "$output" | sed -nE 's/.*[^0-9]([0-9]+)[[:space:]]+missed.*/\1/p' | head -n 1)
    ignored=$(echo "$output" | sed -nE 's/.*[^0-9]([0-9]+)[[:space:]]+ignored.*/\1/p' | head -n 1)
    echo -e "${CYAN}规则测试结果：${RESET}"
    echo "日志总行数: ${lines:-未知}"
    echo "匹配数量: ${matched:-0}"
    echo "未匹配数量: ${missed:-0}"
    echo "忽略数量: ${ignored:-0}"
    if [ "$rc" -eq 0 ] && echo "$output" | grep -Eq "[1-9][0-9]* matched|Failregex:[[:space:]]+[1-9]"; then
        echo -e "${INFO} ${GREEN}规则测试成功且存在匹配。${RESET}"; return 0
    fi
    echo -e "${ERROR} 规则测试未通过或没有匹配日志，请检查语法、日志格式与路径。"
    echo -e "${YELLOW}详细错误信息：${RESET}"
    echo "$output" | tail -n 12
    return 1
}

test_custom_rule() {
    local jail=${1:-} file filter log filter_file
    if [ -z "$jail" ]; then
        echo -e "已有自定义 Jail: ${YELLOW}$(list_custom_jails | xargs)${RESET}"
        read -rp "输入 Jail 名称: " jail
    fi
    validate_f2b_name "$jail" || { echo -e "${ERROR} Jail 名称无效。"; return 1; }
    file=$(find_custom_jail_file "$jail") || { echo -e "${ERROR} 找不到该自定义 Jail。"; return 1; }
    filter=$(read_jail_value "$file" filter); log=$(read_jail_value "$file" logpath)
    [ -f "$log" ] || { echo -e "${ERROR} 日志文件不存在: $log"; return 1; }
    filter_file=$(custom_filter_existing "$filter")
    [ -f "$filter_file" ] || filter_file="$F2B_FILTER_DIR/${filter}.conf"
    [ -f "$filter_file" ] || { echo -e "${ERROR} Filter 文件不存在。"; return 1; }
    run_f2b_regex "$log" "$filter_file"
}

write_custom_rule() {
    local mode=$1 jail=${2:-} old_jail=$2 old_file filter log maxretry findtime bantime action regex jail_tmp filter_tmp
    local jail_file filter_file jail_backup="" filter_backup="" whitelist
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
    if [ -f "$F2B_FILTER_DIR/${filter}.conf" ]; then
        echo -e "${ERROR} Filter 名称与系统 Filter 冲突，请使用唯一名称: $filter"
        return
    fi
    f2b_action_exists "$action" || { echo -e "${ERROR} Fail2Ban action 不存在: $action"; return; }
    echo -e "${CYAN}Filter 用于从日志中识别攻击行为，系统不会自动猜测正则。${RESET}"
    echo -e "${CYAN}请根据实际日志输入 failregex；必须包含 <HOST>（代表待封禁 IP），单行；留空保留现有 Filter。${RESET}"
    echo -e "${GRAY}示例：^.*Login failed from <HOST>.*$${RESET}"
    read -r regex
    filter_tmp=$(mktemp); jail_tmp=$(mktemp)
    if [ -z "$regex" ] && [ -f "$(custom_filter_existing "$dfilter")" ]; then cp "$(custom_filter_existing "$dfilter")" "$filter_tmp"
    elif [[ "$regex" == *'<HOST>'* ]]; then printf '%s\n%s\n%s\n' "$F2B_MANAGED_TAG" '[Definition]' "failregex = $regex" > "$filter_tmp"
    else echo -e "${ERROR} failregex 必须包含 <HOST>。"; rm -f "$filter_tmp" "$jail_tmp"; return; fi
    whitelist=$(get_f2b_whitelist)
    printf '%s\n[%s]\nenabled = true\nfilter = %s\nlogpath = %s\nmaxretry = %s\nfindtime = %s\nbantime = %s\nbantime.increment = false\nbanaction = %s\nignoreip = %s\n' "$F2B_MANAGED_TAG" "$jail" "$filter" "$log" "$maxretry" "$findtime" "$bantime" "$action" "$whitelist" > "$jail_tmp"
    # 在触碰正式配置前先验证实际日志和候选 Filter。
    run_f2b_regex "$log" "$filter_tmp" || { rm -f "$jail_tmp" "$filter_tmp"; return; }
    jail_file=$(custom_jail_file "$jail"); filter_file=$(custom_filter_file "$filter")
    [ -f "$jail_file" ] && { jail_backup=$(mktemp); $SUDO cp "$jail_file" "$jail_backup"; }
    [ -f "$filter_file" ] && { filter_backup=$(mktemp); $SUDO cp "$filter_file" "$filter_backup"; }
    $SUDO mkdir -p "$F2B_JAIL_DIR" "$F2B_FILTER_DIR"
    $SUDO cp "$jail_tmp" "$jail_file"; $SUDO cp "$filter_tmp" "$filter_file"
    rm -f "$jail_tmp" "$filter_tmp"
    if ! test_f2b_config; then
        if [ -n "$jail_backup" ]; then $SUDO cp "$jail_backup" "$jail_file"; else $SUDO rm -f -- "$jail_file"; fi
        if [ -n "$filter_backup" ]; then $SUDO cp "$filter_backup" "$filter_file"; else $SUDO rm -f -- "$filter_file"; fi
        rm -f "$jail_backup" "$filter_backup"
        echo -e "${ERROR} 配置测试失败，Jail 和 Filter 已回滚。"
        return 1
    fi
    rm -f "$jail_backup" "$filter_backup"
    if fail2ban-client ping >/dev/null 2>&1; then $SUDO fail2ban-client reload
    else echo -e "${WARN} 配置测试通过；服务未运行，将在下次启动时生效。"; fi
    echo -e "${INFO} Jail 文件：${jail_file}"
    echo -e "${INFO} Filter 文件：${filter_file}"
}

edit_custom_rule() {
    local jail file
    echo -e "自定义 Jail: ${YELLOW}$(list_custom_jails | xargs)${RESET}"; read -rp "输入要修改的 Jail: " jail
    file=$(find_custom_jail_file "$jail") || { echo -e "${ERROR} Jail 不存在。"; return; }
    grep -qFx "$F2B_MANAGED_TAG" "$file" || { echo -e "${ERROR} 该 Jail 不是本脚本创建的；为避免覆盖手工配置，仅支持查看和测试。"; return; }
    write_custom_rule edit "$jail"
}
delete_custom_rule() {
    local jail file filter filter_file refs jail_backup filter_backup="" remove_filter=0
    echo -e "自定义 Jail: ${YELLOW}$(list_custom_jails | xargs)${RESET}"; read -rp "输入要删除的 Jail: " jail
    validate_f2b_name "$jail" && [ "$jail" != sshd ] || { echo -e "${ERROR} 名称无效。"; return; }
    file=$(custom_jail_file "$jail"); [ -f "$file" ] && grep -qFx "$F2B_MANAGED_TAG" "$file" || { echo -e "${ERROR} 不是本脚本管理的 Jail，拒绝删除。"; return; }
    filter=$(read_jail_value "$file" filter); filter_file=$(custom_filter_existing "$filter")
    echo -e "将删除 Jail: ${RED}$jail${RESET}\n配置: $file\nFilter: $filter_file"
    read -rp "确认删除？(y/N): " confirm; [[ "$confirm" =~ ^[Yy]$ ]] || return
    jail_backup=$(mktemp); $SUDO cp "$file" "$jail_backup"
    $SUDO rm -f -- "$file"
    refs=$(grep -RslE "^[[:space:]]*filter[[:space:]]*=[[:space:]]*${filter}[[:space:]]*$" \
        /etc/fail2ban/jail.conf /etc/fail2ban/jail.local "$F2B_JAIL_DIR" 2>/dev/null | wc -l)
    if [ "$refs" -eq 0 ] && [ -f "$filter_file" ] && grep -qFx "$F2B_MANAGED_TAG" "$filter_file"; then
        filter_backup=$(mktemp); $SUDO cp "$filter_file" "$filter_backup"
        $SUDO rm -f -- "$filter_file"; remove_filter=1
    fi
    if ! test_f2b_config; then
        $SUDO cp "$jail_backup" "$file"
        [ "$remove_filter" -eq 1 ] && $SUDO cp "$filter_backup" "$filter_file"
        rm -f "$jail_backup" "$filter_backup"
        echo -e "${ERROR} 删除后的配置测试失败，Jail 和 Filter 已恢复。"
        return 1
    fi
    rm -f "$jail_backup" "$filter_backup"
    if fail2ban-client ping >/dev/null 2>&1; then $SUDO fail2ban-client reload
    else echo -e "${WARN} 配置测试通过；服务未运行，删除将在下次启动时生效。"; fi
}
view_custom_rules() {
    local jail file filter filter_file
    for jail in $(list_custom_jails); do
        file=$(find_custom_jail_file "$jail") || continue
        filter=$(read_jail_value "$file" filter)
        filter_file=$(custom_filter_existing "$filter")
        echo -e "\n${CYAN}--- Jail: $jail ($file) ---${RESET}"
        $SUDO sed -n '1,120p' "$file"
        # manual-ban 由 fail2ban-client 手动注入 IP，不依赖日志 Filter。
        if [ "$jail" = manual-ban ] || [ -z "$filter" ]; then
            echo -e "${INFO} 该 Jail 未配置 Filter（手动封禁 Jail，无需日志匹配）。"
            continue
        fi
        echo -e "${CYAN}--- Filter: $filter (${filter_file}) ---${RESET}"
        if [ -f "$filter_file" ]; then
            $SUDO sed -n '1,120p' "$filter_file"
            if command -v fail2ban-regex >/dev/null 2>&1; then
                local log matches
                log=$(read_jail_value "$file" logpath)
                if [ -f "$log" ]; then
                    matches=$($SUDO fail2ban-regex "$log" "$filter_file" 2>/dev/null | sed -nE 's/.*[^0-9]([0-9]+)[[:space:]]+matched.*/\1/p' | head -n1)
                    echo -e "${INFO} 当前日志匹配数量：${matches:-0}"
                else
                    echo -e "${WARN} 日志文件不存在，无法测试：${log}"
                fi
            fi
        else
            echo -e "${ERROR} Filter 文件不存在，规则无法匹配和封禁 IP。"
            echo -e "${YELLOW}请创建：${F2B_FILTER_DIR}/${filter}.conf${RESET}"
        fi
    done
    f2b_pause
}
custom_rules_menu() {
    while true; do
        f2b_clear
        echo -e "\n${BOLD}自定义规则管理${RESET}\n  1. 创建自定义规则\n  2. 修改自定义规则\n  3. 删除自定义规则\n  4. 测试规则\n  5. 查看规则\n  0. 返回"
        read -rp "请选择 [0-5]: " opt
        case "$opt" in 1) write_custom_rule create ;; 2) edit_custom_rule ;; 3) delete_custom_rule ;; 4) test_custom_rule; f2b_pause ;; 5) view_custom_rules ;; 0) return ;; *) echo -e "${ERROR} 无效选项。";; esac
    done
}

f2b_logs_menu() {
    while true; do
        f2b_clear
        echo -e "\n1. 查看最近日志\n2. 查看最近错误\n3. 查看传统日志\n4. 查看封禁/解封审计记录\n0. 返回"
        read -rp "请选择 [0-4]: " opt
        case "$opt" in
            1) if command -v journalctl >/dev/null; then $SUDO journalctl -u fail2ban -n 80 --no-pager; elif [ -f "$LOG_FILE" ]; then tail -n 80 "$LOG_FILE"; fi; f2b_pause ;;
            2) if command -v journalctl >/dev/null; then $SUDO journalctl -u fail2ban -p err -n 80 --no-pager; elif [ -f "$LOG_FILE" ]; then grep -Ei 'error|fail|fatal' "$LOG_FILE" | tail -n 80; fi; f2b_pause ;;
            3) [ -f "$LOG_FILE" ] && tail -n 80 "$LOG_FILE" || echo -e "${WARN} $LOG_FILE 不存在。"; f2b_pause ;;
            4) if [ -f "$LOG_FILE" ]; then grep -E '(Ban|Unban)' "$LOG_FILE" | tail -n 20; else echo -e "${WARN} $LOG_FILE 不存在。"; fi; f2b_pause ;;
            0) return ;; *) echo -e "${ERROR} 无效选项。" ;;
        esac
    done
}

f2b_service_menu() {
    while true; do
        f2b_clear
        echo -e "\n1. 启动\n2. 停止\n3. 重启\n4. 查看状态\n5. 设置开机启动\n6. 取消开机启动\n0. 返回"
        read -rp "请选择 [0-6]: " opt
        case "$opt" in
            1)
                if test_f2b_config >/dev/null 2>&1 && svc_start fail2ban; then
                    echo -e "${INFO} ${GREEN}启动操作成功。${RESET}"
                else
                    echo -e "${ERROR} 启动操作失败。"
                fi
                ;;
            2)
                if svc_stop fail2ban; then
                    echo -e "${INFO} ${GREEN}停止操作成功。${RESET}"
                else
                    echo -e "${ERROR} 停止操作失败。"
                fi
                ;;
            3)
                if restart_f2b >/dev/null 2>&1; then
                    echo -e "${INFO} ${GREEN}重启操作成功。${RESET}"
                else
                    echo -e "${ERROR} 重启操作失败。"
                fi
                ;;
            4)
                local active=1
                case "$INIT_SYS" in
                    systemd) $SUDO systemctl is-active --quiet fail2ban && active=0 ;;
                    openrc) $SUDO rc-service fail2ban status >/dev/null 2>&1 && active=0 ;;
                    sysvinit) $SUDO service fail2ban status >/dev/null 2>&1 && active=0 ;;
                esac
                if [ "$active" -eq 0 ]; then
                    echo -e "${INFO} ${GREEN}服务运行正常。${RESET}"
                else
                    echo -e "${WARN} 服务未运行。"
                fi
                ;;
            5)
                if svc_enable fail2ban; then
                    echo -e "${INFO} ${GREEN}设置开机启动成功。${RESET}"
                else
                    echo -e "${ERROR} 设置开机启动失败。"
                fi
                ;;
            6)
                if svc_disable fail2ban; then
                    echo -e "${INFO} ${GREEN}取消开机启动成功。${RESET}"
                else
                    echo -e "${ERROR} 取消开机启动失败。"
                fi
                ;;
            0) return ;; *) echo -e "${ERROR} 无效选项。"; continue ;;
        esac
        f2b_pause
    done
}

f2b_install_menu() {
    while true; do
        f2b_clear
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
        f2b_clear
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
