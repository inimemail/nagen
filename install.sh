#!/usr/bin/env bash
# install.sh
# Nezha incident focused Agent cleaner / updater / hardener
#
# 目标：
#   针对哪吒 Dashboard RCE / cron 下发命令事件后的 Agent 侧排查与清理。
#
# 设计原则：
#   1. 尽量少误报：
#      - 不把正常内核线程 [kworker/*] 当病毒
#      - 不把正常内核线程 [kdevtmpfs] 当病毒
#      - 不把 Xray 多端口监听当病毒
#      - 不把 crontab 注释 "# (/tmp/tmp.xxx installed on ...)" 当病毒
#      - 不因为单独出现 /tmp 就判病毒
#
#   2. 只自动清理高置信 IOC：
#      - /tmp、/var/tmp、/dev/shm、/run/shm、/shm 下的：
#        xmrig / .xmrig / kinsing / kdevtmpfsi / .kworker / kworker_u8 / kinsingwatch
#      - cron / systemd / shell profile 中包含上述高置信 IOC 的执行项
#
#   3. 中风险可疑项只显示，不自动删除：
#      - curl|bash、wget|sh、base64 -d、chmod +x /tmp、nohup /tmp 等
#      - 这些可能是正常运维脚本，所以只提示人工确认
#
#   4. 哪吒 Agent 必做加固：
#      - disable_command_execute: true
#      - disable_nat: true
#      - disable_auto_update: false
#      - disable_force_update: false
#
# 执行：
#   bash <(curl -fsSL https://raw.githubusercontent.com/inimemail/nagen/main/install.sh)
#
# 可选：
#   NO_UPDATE=1    跳过 Agent 升级
#   NO_CLEAN=1     跳过高置信 IOC 自动清理
#   STRICT=1       额外设置 disable_send_query: true
#   SHOW_DETAIL=1  显示更多细节
#   GH_PROXY='https://ghfast.top/'  GitHub 下载慢时使用
#
# 输出判断：
#   CLEAN       未发现高置信病毒 IOC
#   CLEANED     发现高置信病毒 IOC，已自动清理
#   REVIEW      未发现高置信 IOC，但有中风险可疑项，需要人工确认
#   RISK        Agent 配置存在风险，已修复
#   ERROR       升级或识别失败

set +e
umask 077
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

TS="$(date +%F_%H%M%S)"
LOG="/root/nezha_event_clean_${TS}.log"
QDIR="/root/nezha_event_quarantine_${TS}"
mkdir -p "$QDIR"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C0="\033[0m"
  B="\033[1m"
  DIM="\033[2m"
  GREEN="\033[32m"
  YELLOW="\033[33m"
  RED="\033[31m"
  BLUE="\033[34m"
else
  C0=""
  B=""
  DIM=""
  GREEN=""
  YELLOW=""
  RED=""
  BLUE=""
fi

out()   { printf "%b\n" "$*" | tee -a "$LOG"; }
log()   { printf "%b\n" "$*" >> "$LOG"; }
title() { out ""; out "${B}${BLUE}▶ $*${C0}"; }
ok()    { out "${GREEN}✓${C0} $*"; }
warn()  { out "${YELLOW}!${C0} $*"; }
bad()   { out "${RED}✗${C0} $*"; }
info()  { out "${DIM}- $*${C0}"; }
has()   { command -v "$1" >/dev/null 2>&1; }

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    bad "请用 root 执行"
    exit 1
  fi
}

download() {
  local url="$1"
  local out_file="$2"
  local final_url="${GH_PROXY:-}${url}"

  if has curl; then
    curl -fL --connect-timeout 20 --retry 3 --retry-delay 2 "$final_url" -o "$out_file" >> "$LOG" 2>&1
    return $?
  fi

  if has wget; then
    wget --timeout=25 --tries=3 -O "$out_file" "$final_url" >> "$LOG" 2>&1
    return $?
  fi

  return 127
}

install_pkg() {
  local pkg="$1"
  has "$pkg" && return 0

  warn "缺少 $pkg，尝试自动安装"
  if has apt-get; then
    DEBIAN_FRONTEND=noninteractive apt-get update -y >> "$LOG" 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" curl wget ca-certificates >> "$LOG" 2>&1
  elif has yum; then
    yum install -y "$pkg" curl wget ca-certificates >> "$LOG" 2>&1
  elif has dnf; then
    dnf install -y "$pkg" curl wget ca-certificates >> "$LOG" 2>&1
  elif has apk; then
    apk add --no-cache "$pkg" curl wget ca-certificates >> "$LOG" 2>&1
  fi

  has "$pkg"
}

yaml_get() {
  local file="$1"
  local key="$2"

  [ -f "$file" ] || return 1

  grep -E "^[[:space:]]*${key}[[:space:]]*:" "$file" 2>/dev/null | head -n1 | \
    sed -E "s/^[[:space:]]*${key}[[:space:]]*:[[:space:]]*//; s/[[:space:]]+#.*$//; s/^['\"]//; s/['\"]$//"
}

yaml_set_bool() {
  local file="$1"
  local key="$2"
  local val="$3"

  [ -f "$file" ] || return 1

  if grep -Eq "^[[:space:]]*${key}[[:space:]]*:" "$file"; then
    sed -i -E "s|^[[:space:]]*${key}[[:space:]]*:.*|${key}: ${val}|" "$file"
  else
    printf "\n%s: %s\n" "$key" "$val" >> "$file"
  fi
}

# 高置信 IOC：只命中这些才判为病毒并自动清理。
# 注意：
#   - 不匹配正常 [kworker/0:1]
#   - 不匹配正常 [kdevtmpfs]
#   - .kworker 必须在 tmp/shm 路径下
IOC_PROCESS_REGEX='(^|[[:space:]])(/shm/\.kworker[^[:space:]]*|/dev/shm/\.kworker[^[:space:]]*|/run/shm/\.kworker[^[:space:]]*|/tmp/\.kworker[^[:space:]]*|/var/tmp/\.kworker[^[:space:]]*|/tmp/kdevtmpfsi|/var/tmp/kdevtmpfsi|/dev/shm/kdevtmpfsi|/run/shm/kdevtmpfsi|/tmp/kinsing|/var/tmp/kinsing|/dev/shm/kinsing|/run/shm/kinsing|/tmp/xmrig|/var/tmp/xmrig|/dev/shm/xmrig|/run/shm/xmrig|/tmp/\.xmrig|/var/tmp/\.xmrig|/dev/shm/\.xmrig|/run/shm/\.xmrig|/tmp/kinsingwatch|/var/tmp/kinsingwatch)([[:space:]]|$)|(^|[[:space:]])(kworker_u8|kdevtmpfsi|kinsing|kinsingwatch|xmrig)([[:space:]]|$)'

IOC_LINE_REGEX='(/shm/\.kworker|/dev/shm/\.kworker|/run/shm/\.kworker|/tmp/\.kworker|/var/tmp/\.kworker|/tmp/kdevtmpfsi|/var/tmp/kdevtmpfsi|/dev/shm/kdevtmpfsi|/run/shm/kdevtmpfsi|/tmp/kinsing|/var/tmp/kinsing|/dev/shm/kinsing|/run/shm/kinsing|/tmp/xmrig|/var/tmp/xmrig|/dev/shm/xmrig|/run/shm/xmrig|/tmp/\.xmrig|/var/tmp/\.xmrig|/dev/shm/\.xmrig|/run/shm/\.xmrig|kworker_u8|kdevtmpfsi|kinsingwatch|kinsing|xmrig)'

# 中风险：只提示，不自动删。
SUSP_LINE_REGEX='(curl[[:space:]].*\|[[:space:]]*(sh|bash)|wget[[:space:]].*\|[[:space:]]*(sh|bash)|base64[[:space:]]+-d|chmod[[:space:]]+\+x[[:space:]]+/(tmp|var/tmp|dev/shm|run/shm)|nohup[[:space:]]+/(tmp|var/tmp|dev/shm|run/shm)|/(tmp|var/tmp|dev/shm|run/shm)/[^[:space:]]+[[:space:]]*(&|$))'

SERVICE=""
UNIT=""
AGENT_BIN=""
CONFIG=""
BEFORE_VER=""
AFTER_VER=""

FOUND_IOC_PROCESS=0
FOUND_IOC_FILE=0
FOUND_IOC_PERSIST=0
FOUND_SUSP=0
FOUND_LOW_COMMENT=0
CONFIG_RISK=0
CLEANED_IOC=0
UPDATE_OK=0
UPDATE_FAIL=0

HIT_PROC="$QDIR/high_ioc_process.txt"
HIT_FILE="$QDIR/high_ioc_file.txt"
HIT_PERSIST="$QDIR/high_ioc_persist.txt"
HIT_SUSP="$QDIR/medium_suspicious.txt"
HIT_LOW="$QDIR/low_cron_comment.txt"
HIT_AUTHKEY="$QDIR/authorized_keys.txt"
HIT_PORT="$QDIR/listening_ports.txt"

detect_agent() {
  SERVICE=""
  UNIT=""
  AGENT_BIN=""
  CONFIG=""

  if has systemctl; then
    for s in $(
      {
        systemctl list-units --type=service --all --no-legend 2>/dev/null | awk '{print $1}' | grep -Ei '(^|-)nezha.*agent|nezha-agent' || true
        systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -Ei '(^|-)nezha.*agent|nezha-agent' || true
        echo nezha-agent.service
      } | sed '/^$/d' | sort -u
    ); do
      if systemctl cat "$s" >/dev/null 2>&1; then
        SERVICE="$s"
        break
      fi
    done
  fi

  if [ -n "$SERVICE" ]; then
    UNIT="$(systemctl show -p FragmentPath --value "$SERVICE" 2>/dev/null)"
    local catout
    local exec_line

    catout="$(systemctl cat "$SERVICE" 2>/dev/null)"
    exec_line="$(printf "%s\n" "$catout" | grep -E '^[[:space:]]*ExecStart=' | tail -n1 | sed -E 's/^[[:space:]]*ExecStart=//')"

    if [ -n "$exec_line" ]; then
      AGENT_BIN="$(printf "%s\n" "$exec_line" | grep -Eo '/[^[:space:]]*/nezha-agent|/[^[:space:]]*/agent' | head -n1)"
      CONFIG="$(printf "%s\n" "$exec_line" | sed -nE 's/.*(^|[[:space:]])-c[[:space:]]+([^[:space:]]+).*/\2/p; s/.*(^|[[:space:]])--config[=[:space:]]*([^[:space:]]+).*/\2/p' | tail -n1)"
      CONFIG="$(printf "%s" "$CONFIG" | sed 's/^"//; s/"$//')"
    fi

    if [ -z "$CONFIG" ]; then
      CONFIG="$(printf "%s\n" "$catout" | grep -Eo '/[^[:space:]]*config[^[:space:]]*\.ya?ml' | head -n1)"
    fi
  fi

  if [ -z "$AGENT_BIN" ] || [ ! -x "$AGENT_BIN" ]; then
    for p in \
      /opt/nezha/agent/nezha-agent \
      /opt/nezha/agent/agent \
      /opt/nezha/nezha-agent \
      /usr/local/bin/nezha-agent \
      /usr/bin/nezha-agent; do
      if [ -x "$p" ]; then
        AGENT_BIN="$p"
        break
      fi
    done
  fi

  if [ -z "$CONFIG" ] || [ ! -f "$CONFIG" ]; then
    for p in \
      /opt/nezha/agent/config.yml \
      /opt/nezha/agent/config.yaml \
      /opt/nezha/config.yml \
      /opt/nezha/config.yaml \
      /etc/nezha/config.yml \
      /etc/nezha/config.yaml \
      /usr/local/etc/nezha/config.yml \
      /usr/local/etc/nezha/config.yaml; do
      if [ -f "$p" ]; then
        CONFIG="$p"
        break
      fi
    done
  fi
}

agent_version() {
  local bin="$1"
  [ -x "$bin" ] || return 1
  "$bin" -v 2>/dev/null || "$bin" --version 2>/dev/null || true
}

restart_agent() {
  if [ -n "$SERVICE" ] && has systemctl; then
    systemctl daemon-reload >> "$LOG" 2>&1
    systemctl restart "$SERVICE" >> "$LOG" 2>&1
    sleep 1
    if systemctl is-active --quiet "$SERVICE"; then
      ok "Agent 已重启"
      return 0
    fi
    warn "Agent 重启后不是 active，详情看日志"
    systemctl status "$SERVICE" --no-pager -l >> "$LOG" 2>&1
    return 1
  fi

  warn "未识别到 systemd 服务，跳过自动重启"
  return 1
}

harden_config() {
  title "哪吒 Agent 风险配置修复"

  if [ -z "$CONFIG" ] || [ ! -f "$CONFIG" ]; then
    warn "未找到 Agent 配置文件，跳过配置修复"
    return 1
  fi

  local old_dce old_nat old_auto old_force
  old_dce="$(yaml_get "$CONFIG" disable_command_execute)"
  old_nat="$(yaml_get "$CONFIG" disable_nat)"
  old_auto="$(yaml_get "$CONFIG" disable_auto_update)"
  old_force="$(yaml_get "$CONFIG" disable_force_update)"

  if [ "$old_dce" != "true" ] || [ "$old_nat" != "true" ] || [ "$old_auto" = "true" ] || [ "$old_force" = "true" ]; then
    CONFIG_RISK=1
  fi

  cp -a "$CONFIG" "$CONFIG.bak.${TS}" 2>/dev/null

  yaml_set_bool "$CONFIG" debug false
  yaml_set_bool "$CONFIG" disable_command_execute true
  yaml_set_bool "$CONFIG" disable_nat true
  yaml_set_bool "$CONFIG" disable_auto_update false
  yaml_set_bool "$CONFIG" disable_force_update false

  if [ "${STRICT:-0}" = "1" ]; then
    yaml_set_bool "$CONFIG" disable_send_query true
  fi

  ok "远程命令/在线终端/文件管理：已关闭"
  ok "NAT 任务：已关闭"
  ok "Agent 自动更新：已开启"
  ok "面板强制更新：已开启"
  info "配置备份：$CONFIG.bak.${TS}"

  {
    echo
    echo "--- Nezha Agent key config ---"
    grep -E '^(debug|disable_command_execute|disable_nat|disable_send_query|disable_auto_update|disable_force_update):' "$CONFIG" 2>/dev/null || true
  } >> "$LOG"
}

arch_list() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64 arm" ;;
    armv7l|armv6l|armhf|arm) echo "arm" ;;
    i386|i686) echo "386" ;;
    s390x) echo "s390x" ;;
    riscv64) echo "riscv64" ;;
    *) echo "unknown" ;;
  esac
}

update_agent_once() {
  title "Agent 原地升级一次"

  if [ "${NO_UPDATE:-0}" = "1" ]; then
    warn "NO_UPDATE=1，跳过升级"
    return 0
  fi

  if [ -z "$AGENT_BIN" ] || [ ! -x "$AGENT_BIN" ]; then
    bad "未找到 Agent 二进制，无法自动升级"
    UPDATE_FAIL=1
    return 1
  fi

  install_pkg unzip >/dev/null 2>&1
  if ! has unzip; then
    bad "缺少 unzip，自动安装失败，无法升级"
    UPDATE_FAIL=1
    return 1
  fi

  local os
  os="$(uname -s | tr 'A-Z' 'a-z')"
  if [ "$os" != "linux" ]; then
    bad "当前系统不是 Linux，跳过自动替换升级"
    UPDATE_FAIL=1
    return 1
  fi

  BEFORE_VER="$(agent_version "$AGENT_BIN" | head -n1)"
  [ -n "$BEFORE_VER" ] && info "升级前：$BEFORE_VER"

  local tmpd zip ok_arch newbin
  tmpd="$(mktemp -d)"
  zip="$tmpd/agent.zip"
  ok_arch=""
  newbin=""

  for arch in $(arch_list); do
    [ "$arch" = "unknown" ] && continue

    local url="https://github.com/nezhahq/agent/releases/latest/download/nezha-agent_${os}_${arch}.zip"
    info "下载最新版：linux_${arch}"

    if download "$url" "$zip" && [ -s "$zip" ]; then
      mkdir -p "$tmpd/unzip_$arch"
      unzip -o "$zip" -d "$tmpd/unzip_$arch" >> "$LOG" 2>&1

      newbin="$(find "$tmpd/unzip_$arch" -type f -name 'nezha-agent' 2>/dev/null | head -n1)"
      if [ -n "$newbin" ]; then
        ok_arch="$arch"
        break
      fi
    fi
  done

  if [ -z "$ok_arch" ] || [ -z "$newbin" ]; then
    rm -rf "$tmpd"
    bad "下载最新版 Agent 失败"
    warn "GitHub 慢可用：GH_PROXY='https://ghfast.top/' bash install.sh"
    UPDATE_FAIL=1
    return 1
  fi

  if [ -n "$SERVICE" ] && has systemctl; then
    systemctl stop "$SERVICE" >> "$LOG" 2>&1
  fi

  pkill -f "$AGENT_BIN" >> "$LOG" 2>&1
  sleep 1

  cp -a "$AGENT_BIN" "$AGENT_BIN.bak.${TS}" 2>/dev/null
  install -m 755 "$newbin" "$AGENT_BIN" >> "$LOG" 2>&1
  local rc=$?

  rm -rf "$tmpd"

  if [ "$rc" -ne 0 ]; then
    bad "替换 Agent 二进制失败"
    UPDATE_FAIL=1
    restart_agent
    return 1
  fi

  ok "已替换 Agent 二进制：$ok_arch"
  info "旧二进制备份：$AGENT_BIN.bak.${TS}"

  restart_agent

  AFTER_VER="$(agent_version "$AGENT_BIN" | head -n1)"
  [ -n "$AFTER_VER" ] && info "升级后：$AFTER_VER"

  UPDATE_OK=1
  return 0
}

scan_high_ioc_process() {
  : > "$HIT_PROC"

  ps auxww | awk '
    BEGIN { IGNORECASE=1 }
    {
      line=$0

      # 排除正常内核线程格式：[kworker/...], [kdevtmpfs]
      if (line ~ /\[kworker\//) next
      if (line ~ /\[kdevtmpfs\]/) next

      if (
        line ~ /\/shm\/\.kworker/ ||
        line ~ /\/dev\/shm\/\.kworker/ ||
        line ~ /\/run\/shm\/\.kworker/ ||
        line ~ /\/tmp\/\.kworker/ ||
        line ~ /\/var\/tmp\/\.kworker/ ||
        line ~ /\/tmp\/kdevtmpfsi/ ||
        line ~ /\/var\/tmp\/kdevtmpfsi/ ||
        line ~ /\/dev\/shm\/kdevtmpfsi/ ||
        line ~ /\/run\/shm\/kdevtmpfsi/ ||
        line ~ /\/tmp\/kinsing/ ||
        line ~ /\/var\/tmp\/kinsing/ ||
        line ~ /\/dev\/shm\/kinsing/ ||
        line ~ /\/run\/shm\/kinsing/ ||
        line ~ /\/tmp\/xmrig/ ||
        line ~ /\/var\/tmp\/xmrig/ ||
        line ~ /\/dev\/shm\/xmrig/ ||
        line ~ /\/run\/shm\/xmrig/ ||
        line ~ /\/tmp\/\.xmrig/ ||
        line ~ /\/var\/tmp\/\.xmrig/ ||
        line ~ /\/dev\/shm\/\.xmrig/ ||
        line ~ /\/run\/shm\/\.xmrig/ ||
        line ~ /\/tmp\/kinsingwatch/ ||
        line ~ /\/var\/tmp\/kinsingwatch/ ||
        line ~ /(^|[[:space:]])kworker_u8([[:space:]]|$)/ ||
        line ~ /(^|[[:space:]])kdevtmpfsi([[:space:]]|$)/ ||
        line ~ /(^|[[:space:]])kinsing([[:space:]]|$)/ ||
        line ~ /(^|[[:space:]])kinsingwatch([[:space:]]|$)/ ||
        line ~ /(^|[[:space:]])xmrig([[:space:]]|$)/
      ) print line
    }
  ' > "$HIT_PROC" 2>/dev/null

  if [ -s "$HIT_PROC" ]; then
    FOUND_IOC_PROCESS=1
    bad "发现高置信挖矿进程"
    out ""
    out "${B}命中进程：${C0}"
    head -20 "$HIT_PROC" | tee -a "$LOG"
  else
    ok "未发现高置信挖矿进程"
  fi
}

scan_high_ioc_files() {
  : > "$HIT_FILE"

  for f in \
    /shm/.kworker* \
    /dev/shm/.kworker* \
    /run/shm/.kworker* \
    /tmp/.kworker* \
    /var/tmp/.kworker* \
    /tmp/kdevtmpfsi \
    /var/tmp/kdevtmpfsi \
    /dev/shm/kdevtmpfsi \
    /run/shm/kdevtmpfsi \
    /tmp/kinsing \
    /var/tmp/kinsing \
    /dev/shm/kinsing \
    /run/shm/kinsing \
    /tmp/xmrig \
    /var/tmp/xmrig \
    /dev/shm/xmrig \
    /run/shm/xmrig \
    /tmp/.xmrig \
    /var/tmp/.xmrig \
    /dev/shm/.xmrig \
    /run/shm/.xmrig \
    /tmp/kinsingwatch \
    /var/tmp/kinsingwatch; do
    [ -e "$f" ] && printf "%s\n" "$f" >> "$HIT_FILE"
  done

  find /tmp /var/tmp /dev/shm /run/shm -maxdepth 2 -xdev 2>/dev/null | \
    grep -Ei '(^|/)(\.kworker.*|kdevtmpfsi|kinsing|xmrig|\.xmrig|kinsingwatch)$' >> "$HIT_FILE" 2>/dev/null

  sort -u "$HIT_FILE" -o "$HIT_FILE"

  if [ -s "$HIT_FILE" ]; then
    FOUND_IOC_FILE=1
    bad "发现高置信挖矿文件"
    out ""
    out "${B}命中文件：${C0}"
    head -30 "$HIT_FILE" | tee -a "$LOG"
  else
    ok "未发现高置信挖矿文件"
  fi
}

scan_persistence() {
  : > "$HIT_PERSIST"
  : > "$HIT_SUSP"
  : > "$HIT_LOW"

  local targets
  targets="
/etc/crontab
/etc/cron.d
/etc/cron.daily
/etc/cron.hourly
/etc/cron.weekly
/etc/cron.monthly
/var/spool/cron
/var/spool/cron/crontabs
/etc/systemd/system
/lib/systemd/system
/usr/lib/systemd/system
/root/.bashrc
/root/.profile
/root/.bash_profile
/etc/profile
/etc/bash.bashrc
/etc/profile.d
"

  # 高置信持久化：必须含具体 IOC 名称/路径。
  grep -REin "$IOC_LINE_REGEX" $targets 2>/dev/null | \
    grep -Ev '^[^:]+:[0-9]+:[[:space:]]*#' > "$HIT_PERSIST"

  # 中风险：下载执行、base64、临时目录可执行；注释行不算。
  grep -REin "$SUSP_LINE_REGEX" $targets 2>/dev/null | \
    grep -Ev '^[^:]+:[0-9]+:[[:space:]]*#' > "$HIT_SUSP"

  # 低风险 crontab 注释：不算病毒，只清理误报。
  grep -REin '^# \(/tmp/tmp\.[^)]* installed on ' /var/spool/cron /var/spool/cron/crontabs 2>/dev/null > "$HIT_LOW"

  if [ -s "$HIT_PERSIST" ]; then
    FOUND_IOC_PERSIST=1
    bad "发现高置信挖矿自启动"
    out ""
    out "${B}命中自启动：${C0}"
    head -30 "$HIT_PERSIST" | tee -a "$LOG"
  else
    ok "未发现高置信挖矿自启动"
  fi

  if [ -s "$HIT_SUSP" ]; then
    FOUND_SUSP=1
    warn "发现中风险可疑启动项，只提示不自动删除"
    out ""
    out "${B}中风险可疑项：${C0}"
    head -20 "$HIT_SUSP" | tee -a "$LOG"
  else
    ok "未发现中风险可疑启动项"
  fi

  if [ -s "$HIT_LOW" ]; then
    FOUND_LOW_COMMENT=1
    warn "发现 crontab 临时文件注释，低风险，稍后自动清理误报"
    out ""
    out "${B}低风险注释：${C0}"
    head -10 "$HIT_LOW" | tee -a "$LOG"
  fi
}

scan_security_context() {
  {
    echo
    echo "--- last -ai ---"
    last -ai 2>/dev/null | head -50 || true

    echo
    echo "--- authorized_keys ---"
    if [ -f /root/.ssh/authorized_keys ]; then
      echo "/root/.ssh/authorized_keys"
      nl -ba /root/.ssh/authorized_keys
    fi
    for ak in /home/*/.ssh/authorized_keys; do
      [ -f "$ak" ] || continue
      echo "$ak"
      nl -ba "$ak"
    done

    echo
    echo "--- listening ports ---"
    ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null || true

    echo
    echo "--- top cpu ---"
    ps auxww --sort=-%cpu | head -20

    echo
    echo "--- top mem ---"
    ps auxww --sort=-%mem | head -20

    if has docker; then
      echo
      echo "--- docker ps -a ---"
      docker ps -a 2>/dev/null
      echo
      echo "--- docker images ---"
      docker images 2>/dev/null
    fi
  } >> "$LOG"
}

scan_all() {
  title "哪吒事件专项 IOC 扫描"

  scan_high_ioc_process
  scan_high_ioc_files
  scan_persistence
  scan_security_context

  info "登录记录、SSH Key、端口、高占用进程已写入日志"
}

kill_ioc_processes() {
  local killed=0

  # 精准杀高置信名称，避免误杀正常 kworker/kdevtmpfs
  for pat in \
    '/shm/.kworker' \
    '/dev/shm/.kworker' \
    '/run/shm/.kworker' \
    '/tmp/.kworker' \
    '/var/tmp/.kworker' \
    '/tmp/kdevtmpfsi' \
    '/var/tmp/kdevtmpfsi' \
    '/dev/shm/kdevtmpfsi' \
    '/run/shm/kdevtmpfsi' \
    '/tmp/kinsing' \
    '/var/tmp/kinsing' \
    '/dev/shm/kinsing' \
    '/run/shm/kinsing' \
    '/tmp/xmrig' \
    '/var/tmp/xmrig' \
    '/dev/shm/xmrig' \
    '/run/shm/xmrig' \
    '/tmp/.xmrig' \
    '/var/tmp/.xmrig' \
    '/dev/shm/.xmrig' \
    '/run/shm/.xmrig' \
    '/tmp/kinsingwatch' \
    '/var/tmp/kinsingwatch' \
    'kworker_u8' \
    'kdevtmpfsi' \
    'kinsing' \
    'kinsingwatch' \
    'xmrig'; do

    local pids
    pids="$(pgrep -f "$pat" 2>/dev/null)"

    # 避免把内核线程误杀：pgrep -f 理论上不会杀 [kworker/...]
    if [ -n "$pids" ]; then
      echo "kill pattern=$pat pids=$pids" >> "$LOG"
      kill $pids >> "$LOG" 2>&1
      sleep 1
      kill -9 $pids >> "$LOG" 2>&1
      killed=1
      CLEANED_IOC=1
    fi
  done

  [ "$killed" = "1" ] && ok "已终止高置信挖矿进程" || ok "无需终止挖矿进程"
}

quarantine_rm() {
  local f="$1"
  [ -e "$f" ] || return 0

  chattr -i "$f" >> "$LOG" 2>&1
  cp -a "$f" "$QDIR/" >> "$LOG" 2>&1
  rm -rf "$f" >> "$LOG" 2>&1
  echo "$f" >> "$QDIR/removed_files.txt"
  CLEANED_IOC=1
}

clean_ioc_files() {
  local removed=0

  if [ -s "$HIT_FILE" ]; then
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      if [ -e "$f" ]; then
        quarantine_rm "$f"
        removed=1
      fi
    done < "$HIT_FILE"
  fi

  rmdir /shm >> "$LOG" 2>&1

  [ "$removed" = "1" ] && ok "已隔离删除高置信挖矿文件" || ok "无需删除挖矿文件"
}

clean_ioc_line_in_file() {
  local file="$1"
  [ -f "$file" ] || return 0

  if grep -Eiq "$IOC_LINE_REGEX" "$file"; then
    cp -a "$file" "$QDIR/$(echo "$file" | tr '/' '_').bak" 2>/dev/null
    local tmpf
    tmpf="$(mktemp)"
    grep -Eiv "$IOC_LINE_REGEX" "$file" > "$tmpf"
    cat "$tmpf" > "$file"
    rm -f "$tmpf"
    echo "$file" >> "$QDIR/cleaned_persist_files.txt"
    CLEANED_IOC=1
  fi
}

clean_persistence_high_ioc() {
  local changed=0

  clean_ioc_line_in_file /etc/crontab

  for f in \
    /etc/cron.d/* \
    /etc/cron.daily/* \
    /etc/cron.hourly/* \
    /etc/cron.weekly/* \
    /etc/cron.monthly/* \
    /var/spool/cron/* \
    /var/spool/cron/crontabs/* \
    /root/.bashrc \
    /root/.profile \
    /root/.bash_profile \
    /etc/profile \
    /etc/bash.bashrc \
    /etc/profile.d/*; do
    clean_ioc_line_in_file "$f"
  done

  local tmpcron
  tmpcron="$(mktemp)"
  crontab -l 2>/dev/null > "$tmpcron"
  if grep -Eiq "$IOC_LINE_REGEX" "$tmpcron"; then
    cp "$tmpcron" "$QDIR/current_user_crontab.bak" 2>/dev/null
    grep -Eiv "$IOC_LINE_REGEX" "$tmpcron" | crontab -
    echo "current_user_crontab" >> "$QDIR/cleaned_persist_files.txt"
    CLEANED_IOC=1
  fi
  rm -f "$tmpcron"

  local found_units
  found_units="$(grep -RIlE "$IOC_LINE_REGEX" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null)"
  for f in $found_units; do
    cp -a "$f" "$QDIR/$(echo "$f" | tr '/' '_').bak" 2>/dev/null
    local svc
    svc="$(basename "$f")"
    systemctl disable --now "$svc" >> "$LOG" 2>&1
    chattr -i "$f" >> "$LOG" 2>&1
    mv "$f" "$f.disabled_by_nezha_event_clean_${TS}" >> "$LOG" 2>&1
    echo "$f" >> "$QDIR/cleaned_persist_files.txt"
    CLEANED_IOC=1
  done

  has systemctl && systemctl daemon-reload >> "$LOG" 2>&1

  if [ -f /etc/ld.so.preload ]; then
    if grep -Eq '/tmp/|/var/tmp/|/dev/shm|/run/shm' /etc/ld.so.preload; then
      cp -a /etc/ld.so.preload "$QDIR/ld.so.preload.bak" 2>/dev/null
      : > /etc/ld.so.preload
      echo "/etc/ld.so.preload" >> "$QDIR/cleaned_persist_files.txt"
      CLEANED_IOC=1
    fi
  fi

  if [ -s "$QDIR/cleaned_persist_files.txt" ]; then
    changed=1
  fi

  [ "$changed" = "1" ] && ok "已清理高置信挖矿自启动" || ok "无需清理高置信挖矿自启动"
}

clean_low_cron_comment() {
  local changed=0
  local tmp

  tmp="$(mktemp)"
  crontab -l 2>/dev/null > "$tmp"
  if grep -Eq '^# \(/tmp/tmp\.[^)]* installed on ' "$tmp"; then
    cp "$tmp" "$QDIR/current_user_crontab_before_comment_clean.bak" 2>/dev/null
    grep -Ev '^# \(/tmp/tmp\.[^)]* installed on ' "$tmp" | crontab -
    changed=1
  fi
  rm -f "$tmp"

  for f in /var/spool/cron/crontabs/* /var/spool/cron/*; do
    [ -f "$f" ] || continue
    if grep -Eq '^# \(/tmp/tmp\.[^)]* installed on ' "$f"; then
      cp -a "$f" "$QDIR/$(echo "$f" | tr '/' '_').low_comment.bak" 2>/dev/null
      sed -i -E '/^# \(\/tmp\/tmp\.[^)]* installed on /d' "$f"
      changed=1
    fi
  done

  [ "$changed" = "1" ] && ok "已清理 crontab 临时文件注释误报" || ok "没有 crontab 临时文件注释需要清理"
}

clean_high_ioc() {
  title "高置信 IOC 自动清理"

  if [ "${NO_CLEAN:-0}" = "1" ]; then
    warn "NO_CLEAN=1，跳过清理"
    return 0
  fi

  kill_ioc_processes
  clean_ioc_files
  clean_persistence_high_ioc
  clean_low_cron_comment
}

show_review_tips() {
  if [ "$FOUND_SUSP" = "1" ]; then
    out ""
    warn "中风险项没有自动删除，因为可能是正常运维命令。请人工看上面列出的行。"
    info "重点看是否是陌生下载执行、base64 解码执行、/tmp 下可执行文件。"
  fi
}

final_verdict() {
  title "最终结果"

  detect_agent

  out "服务：${SERVICE:-未识别}"
  out "二进制：${AGENT_BIN:-未识别}"
  out "配置：${CONFIG:-未识别}"

  if [ -n "$AGENT_BIN" ] && [ -x "$AGENT_BIN" ]; then
    local v
    v="$(agent_version "$AGENT_BIN" | head -n1)"
    [ -n "$v" ] && out "版本：$v"
  fi

  if [ -f "$CONFIG" ]; then
    local dce dna dau dfu
    dce="$(yaml_get "$CONFIG" disable_command_execute)"
    dna="$(yaml_get "$CONFIG" disable_nat)"
    dau="$(yaml_get "$CONFIG" disable_auto_update)"
    dfu="$(yaml_get "$CONFIG" disable_force_update)"

    out "远程命令/终端/文件：$([ "$dce" = "true" ] && echo "已关闭" || echo "未确认")"
    out "NAT任务：$([ "$dna" = "true" ] && echo "已关闭" || echo "未确认")"
    out "自动更新：$([ "$dau" = "false" ] && echo "已开启" || echo "未确认")"
    out "面板强更：$([ "$dfu" = "false" ] && echo "已开启" || echo "未确认")"
  fi

  out ""

  if [ "$FOUND_IOC_PROCESS" = "1" ] || [ "$FOUND_IOC_FILE" = "1" ] || [ "$FOUND_IOC_PERSIST" = "1" ]; then
    bad "结论：CLEANED - 发现高置信挖矿 IOC，已自动清理。建议观察是否复发，复发就重装系统。"
  elif [ "$FOUND_SUSP" = "1" ]; then
    warn "结论：REVIEW - 未发现高置信挖矿 IOC，但存在中风险可疑项，需要人工确认。"
  elif [ "$CONFIG_RISK" = "1" ]; then
    warn "结论：RISK - 未发现高置信挖矿 IOC，但 Agent 风险配置已被修复。"
  elif [ "$FOUND_LOW_COMMENT" = "1" ]; then
    ok "结论：CLEAN - 只发现 crontab 临时文件注释误报，不是挖矿病毒，已清理。"
  else
    ok "结论：CLEAN - 未发现高置信哪吒事件常见挖矿 IOC。"
  fi

  if [ "$UPDATE_OK" = "1" ]; then
    ok "Agent 升级：已原地升级一次"
  elif [ "${NO_UPDATE:-0}" = "1" ]; then
    warn "Agent 升级：已按 NO_UPDATE=1 跳过"
  elif [ "$UPDATE_FAIL" = "1" ]; then
    bad "Agent 升级：失败，详情看日志"
  else
    warn "Agent 升级：未确认"
  fi

  out ""
  out "日志：$LOG"
  out "隔离目录：$QDIR"
}

main() {
  need_root

  out "${B}Nezha 事件专项 Agent 排查 / 清理 / 升级${C0}"
  out "${DIM}日志：$LOG${C0}"

  title "识别 Agent"
  detect_agent

  if [ -n "$SERVICE" ]; then ok "服务：$SERVICE"; else warn "未识别到 systemd 服务"; fi
  if [ -n "$AGENT_BIN" ]; then ok "二进制：$AGENT_BIN"; else bad "未识别到 Agent 二进制"; fi
  if [ -n "$CONFIG" ]; then ok "配置：$CONFIG"; else warn "未识别到配置文件"; fi

  if [ -n "$AGENT_BIN" ] && [ -x "$AGENT_BIN" ]; then
    BEFORE_VER="$(agent_version "$AGENT_BIN" | head -n1)"
    [ -n "$BEFORE_VER" ] && info "当前版本：$BEFORE_VER"
  fi

  scan_all
  harden_config
  restart_agent
  update_agent_once

  detect_agent
  harden_config
  restart_agent

  clean_high_ioc

  # 清理后再扫一次，给最终判断更准确。
  scan_all
  show_review_tips
  final_verdict
}

main "$@"
