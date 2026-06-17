#!/usr/bin/env bash
# install.sh
# Nezha Agent clean + update + harden
#
# 适用场景：
#   - 机器已经安装了哪吒 Agent
#   - 不想手填 UUID / server / client_secret
#   - 只想原地排查、清理、升级一次，并保留 Agent 自动更新
#
# 执行：
#   bash <(curl -fsSL https://raw.githubusercontent.com/inimemail/nagen/main/install.sh)
#
# 可选：
#   NO_UPDATE=1 bash install.sh           # 不升级，只排查清理加固
#   NO_CLEAN=1 bash install.sh            # 不清理，只升级加固排查
#   STRICT=1 bash install.sh              # 额外禁用 Agent 主动检测任务 disable_send_query
#   SHOW_DETAIL=1 bash install.sh         # 终端显示详细排查内容
#   GH_PROXY='https://ghfast.top/' bash install.sh
#
# 说明：
#   - 脚本只处理 nezha-agent，不删除 Dashboard 数据库/面板目录/Docker 卷。
#   - 会保留现有 Agent 配置里的 uuid/server/client_secret。
#   - 会把 disable_auto_update / disable_force_update 设置为 false，保留自动更新和面板强制更新。
#   - 会把 disable_command_execute 设置为 true，关闭远程命令/在线终端/文件管理能力。

set +e
umask 077
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

TS="$(date +%F_%H%M%S)"
LOG="/root/nezha_agent_clean_${TS}.log"
QDIR="/root/nezha_quarantine_${TS}"
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

log_raw() { printf "%b\n" "$*" >> "$LOG"; }
out()     { printf "%b\n" "$*" | tee -a "$LOG"; }
title()   { out ""; out "${B}${BLUE}▶ $*${C0}"; }
ok()      { out "${GREEN}✓${C0} $*"; }
warn()    { out "${YELLOW}!${C0} $*"; }
bad()     { out "${RED}✗${C0} $*"; }
info()    { out "${DIM}- $*${C0}"; }

run_bg() {
  "$@" >> "$LOG" 2>&1
  return $?
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    bad "请用 root 执行"
    exit 1
  fi
}

has() {
  command -v "$1" >/dev/null 2>&1
}

download() {
  local url="$1"
  local out="$2"
  local final_url="${GH_PROXY:-}${url}"

  if has curl; then
    curl -fL --connect-timeout 20 --retry 3 --retry-delay 2 "$final_url" -o "$out" >> "$LOG" 2>&1
    return $?
  fi

  if has wget; then
    wget --timeout=25 --tries=3 -O "$out" "$final_url" >> "$LOG" 2>&1
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

yaml_get() {
  local file="$1"
  local key="$2"

  [ -f "$file" ] || return 1

  grep -E "^[[:space:]]*${key}[[:space:]]*:" "$file" 2>/dev/null | head -n1 | \
    sed -E "s/^[[:space:]]*${key}[[:space:]]*:[[:space:]]*//; s/[[:space:]]+#.*$//; s/^['\"]//; s/['\"]$//"
}

IOC_REGEX='(/shm/\.kworker|/dev/shm/\.kworker|/run/shm/\.kworker|/tmp/\.kworker|/var/tmp/\.kworker|kworker_u8|kdevtmpfsi|kinsing|xmrig|\.xmrig|kinsingwatch)'
SUSP_REGEX='(/tmp/|/var/tmp/|/dev/shm/|/run/shm/|curl .*\| *sh|wget .*\| *sh|base64[[:space:]]+-d|chmod[[:space:]]+\+x .*/tmp|nohup .*/tmp|python.*http|perl.*http)'

SERVICE=""
UNIT=""
AGENT_BIN=""
CONFIG=""
BEFORE_VER=""
AFTER_VER=""

FOUND_PROC=0
FOUND_FILE=0
FOUND_PERSIST=0
FOUND_SUSP=0
UPDATE_OK=0
UPDATE_FAIL=0

HIT_PROC="$QDIR/hit_process.txt"
HIT_FILE="$QDIR/hit_file.txt"
HIT_PERSIST="$QDIR/hit_persist.txt"
HIT_SUSP="$QDIR/hit_suspicious.txt"

detect_agent() {
  SERVICE=""
  UNIT=""
  AGENT_BIN=""
  CONFIG=""

  if has systemctl; then
    for s in $(
      {
        systemctl list-units --type=service --all --no-legend 2>/dev/null | awk '{print $1}' | grep -Ei 'nezha.*agent|nezha-agent' || true
        systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -Ei 'nezha.*agent|nezha-agent' || true
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
    warn "Agent 重启后不是 active，详情看日志：$LOG"
    systemctl status "$SERVICE" --no-pager -l >> "$LOG" 2>&1
    return 1
  fi

  warn "未识别到 systemd 服务，跳过自动重启"
  return 1
}

harden_config() {
  title "加固 Agent 配置"

  if [ -z "$CONFIG" ] || [ ! -f "$CONFIG" ]; then
    warn "未找到 Agent 配置文件，跳过配置加固"
    return 1
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

  ok "已关闭远程命令/终端/文件管理能力"
  ok "已关闭 NAT 任务"
  ok "已保留 Agent 自动更新和面板强制更新"
  info "配置备份：$CONFIG.bak.${TS}"

  {
    echo "--- key config ---"
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
  title "自动升级 Agent 一次"

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

  local tmpd
  tmpd="$(mktemp -d)"
  local zip="$tmpd/agent.zip"
  local ok_arch=""
  local newbin=""

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
    warn "如果 GitHub 慢，可用：GH_PROXY='https://ghfast.top/' bash install.sh"
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

scan_ioc() {
  title "扫描病毒/挖矿 IOC"

  : > "$HIT_PROC"
  : > "$HIT_FILE"
  : > "$HIT_PERSIST"
  : > "$HIT_SUSP"

  ps auxww | grep -Ei "$IOC_REGEX" | grep -v grep > "$HIT_PROC" 2>/dev/null
  if [ -s "$HIT_PROC" ]; then
    FOUND_PROC=1
    bad "发现已知挖矿进程"
  else
    ok "未发现已知挖矿进程"
  fi

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
    FOUND_FILE=1
    bad "发现已知挖矿文件"
  else
    ok "未发现已知挖矿文件"
  fi

  grep -REin "$IOC_REGEX" \
    /etc/crontab \
    /etc/cron.d \
    /etc/cron.daily \
    /etc/cron.hourly \
    /etc/cron.weekly \
    /etc/cron.monthly \
    /var/spool/cron \
    /var/spool/cron/crontabs \
    /etc/systemd/system \
    /lib/systemd/system \
    /usr/lib/systemd/system \
    /root/.bashrc \
    /root/.profile \
    /root/.bash_profile \
    /etc/profile \
    /etc/bash.bashrc \
    /etc/profile.d \
    2>/dev/null > "$HIT_PERSIST"

  if [ -s "$HIT_PERSIST" ]; then
    FOUND_PERSIST=1
    bad "发现已知挖矿自启动残留"
  else
    ok "未发现已知挖矿自启动残留"
  fi

  grep -REin "$SUSP_REGEX" \
    /etc/crontab \
    /etc/cron.d \
    /etc/cron.daily \
    /etc/cron.hourly \
    /etc/cron.weekly \
    /etc/cron.monthly \
    /var/spool/cron \
    /var/spool/cron/crontabs \
    /etc/systemd/system \
    /lib/systemd/system \
    /usr/lib/systemd/system \
    /root/.bashrc \
    /root/.profile \
    /root/.bash_profile \
    /etc/profile \
    /etc/bash.bashrc \
    /etc/profile.d \
    2>/dev/null > "$HIT_SUSP"

  if [ -s "$HIT_SUSP" ]; then
    FOUND_SUSP=1
    warn "发现可疑启动项，需要人工确认"
  else
    ok "未发现明显可疑启动项"
  fi

  {
    echo
    echo "--- hit process ---"
    cat "$HIT_PROC" 2>/dev/null
    echo
    echo "--- hit file ---"
    cat "$HIT_FILE" 2>/dev/null
    echo
    echo "--- hit persist ---"
    cat "$HIT_PERSIST" 2>/dev/null
    echo
    echo "--- suspicious ---"
    cat "$HIT_SUSP" 2>/dev/null
  } >> "$LOG"

  if [ "${SHOW_DETAIL:-0}" = "1" ]; then
    [ -s "$HIT_PROC" ] && { out ""; out "${B}命中进程：${C0}"; cat "$HIT_PROC" | tee -a "$LOG"; }
    [ -s "$HIT_FILE" ] && { out ""; out "${B}命中文件：${C0}"; cat "$HIT_FILE" | tee -a "$LOG"; }
    [ -s "$HIT_PERSIST" ] && { out ""; out "${B}命中自启动：${C0}"; cat "$HIT_PERSIST" | tee -a "$LOG"; }
    [ -s "$HIT_SUSP" ] && { out ""; out "${B}可疑项：${C0}"; cat "$HIT_SUSP" | head -80 | tee -a "$LOG"; }
  else
    info "详细命中已写入日志：$LOG"
  fi
}

kill_ioc_processes() {
  local killed=0

  for pat in \
    '/shm/.kworker' \
    '/dev/shm/.kworker' \
    '/run/shm/.kworker' \
    '/tmp/.kworker' \
    '/var/tmp/.kworker' \
    'kworker_u8' \
    'kdevtmpfsi' \
    'kinsing' \
    'xmrig' \
    '.xmrig' \
    'kinsingwatch'; do

    local pids
    pids="$(pgrep -f "$pat" 2>/dev/null)"
    if [ -n "$pids" ]; then
      echo "kill $pat: $pids" >> "$LOG"
      kill $pids >> "$LOG" 2>&1
      sleep 1
      kill -9 $pids >> "$LOG" 2>&1
      killed=1
    fi
  done

  [ "$killed" = "1" ] && ok "已终止已知挖矿进程" || ok "无需终止挖矿进程"
}

quarantine_rm() {
  local f="$1"
  [ -e "$f" ] || return 0

  chattr -i "$f" >> "$LOG" 2>&1
  cp -a "$f" "$QDIR/" >> "$LOG" 2>&1
  rm -rf "$f" >> "$LOG" 2>&1
  echo "$f" >> "$QDIR/removed_files.txt"
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

  [ "$removed" = "1" ] && ok "已隔离删除已知挖矿文件" || ok "无需删除挖矿文件"
}

clean_file_ioc_lines() {
  local file="$1"
  [ -f "$file" ] || return 0

  if grep -Eiq "$IOC_REGEX" "$file"; then
    cp -a "$file" "$QDIR/$(echo "$file" | tr '/' '_').bak" 2>/dev/null
    local tmpf
    tmpf="$(mktemp)"
    grep -Eiv "$IOC_REGEX" "$file" > "$tmpf"
    cat "$tmpf" > "$file"
    rm -f "$tmpf"
    echo "$file" >> "$QDIR/cleaned_persist_files.txt"
  fi
}

clean_persistence() {
  local changed=0

  clean_file_ioc_lines /etc/crontab

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
    clean_file_ioc_lines "$f"
  done

  local tmpcron
  tmpcron="$(mktemp)"
  crontab -l 2>/dev/null > "$tmpcron"
  if grep -Eiq "$IOC_REGEX" "$tmpcron"; then
    cp "$tmpcron" "$QDIR/current_user_crontab.bak" 2>/dev/null
    grep -Eiv "$IOC_REGEX" "$tmpcron" | crontab -
    echo "current_user_crontab" >> "$QDIR/cleaned_persist_files.txt"
  fi
  rm -f "$tmpcron"

  local found_units
  found_units="$(grep -RIlE "$IOC_REGEX" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null)"
  for f in $found_units; do
    cp -a "$f" "$QDIR/$(echo "$f" | tr '/' '_').bak" 2>/dev/null
    local svc
    svc="$(basename "$f")"
    systemctl disable --now "$svc" >> "$LOG" 2>&1
    chattr -i "$f" >> "$LOG" 2>&1
    mv "$f" "$f.disabled_by_nezha_clean_${TS}" >> "$LOG" 2>&1
    echo "$f" >> "$QDIR/cleaned_persist_files.txt"
  done

  has systemctl && systemctl daemon-reload >> "$LOG" 2>&1

  if [ -f /etc/ld.so.preload ]; then
    if grep -Eq '/tmp/|/var/tmp/|/dev/shm|/run/shm' /etc/ld.so.preload; then
      cp -a /etc/ld.so.preload "$QDIR/ld.so.preload.bak" 2>/dev/null
      : > /etc/ld.so.preload
      echo "/etc/ld.so.preload" >> "$QDIR/cleaned_persist_files.txt"
    fi
  fi

  if [ -s "$QDIR/cleaned_persist_files.txt" ]; then
    changed=1
  fi

  [ "$changed" = "1" ] && ok "已清理已知挖矿自启动残留" || ok "无需清理已知自启动残留"
}

clean_ioc() {
  title "清理已知 IOC"

  if [ "${NO_CLEAN:-0}" = "1" ]; then
    warn "NO_CLEAN=1，跳过清理"
    return 0
  fi

  kill_ioc_processes
  clean_ioc_files
  clean_persistence
}

security_checks() {
  title "基础安全排查"

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

  ok "最近登录、SSH Key、监听端口、高占用进程已写入日志"
  info "日志：$LOG"

  if [ "${SHOW_DETAIL:-0}" = "1" ]; then
    out ""
    out "${B}监听端口：${C0}"
    ss -lntup 2>/dev/null | tee -a "$LOG" || netstat -lntup 2>/dev/null | tee -a "$LOG" || true
    out ""
    out "${B}CPU Top：${C0}"
    ps auxww --sort=-%cpu | head -12 | tee -a "$LOG"
  fi
}

final_verdict() {
  title "结果"

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

    out "远程命令：$([ "$dce" = "true" ] && echo "已关闭" || echo "未确认")"
    out "NAT任务：$([ "$dna" = "true" ] && echo "已关闭" || echo "未确认")"
    out "自动更新：$([ "$dau" = "false" ] && echo "已开启" || echo "未确认")"
    out "面板强更：$([ "$dfu" = "false" ] && echo "已开启" || echo "未确认")"
  fi

  out ""
  if [ "$FOUND_PROC" = "1" ] || [ "$FOUND_FILE" = "1" ] || [ "$FOUND_PERSIST" = "1" ]; then
    bad "病毒判断：发现已知挖矿 IOC，已尝试清理。建议继续观察，反复出现就重装系统。"
  elif [ "$FOUND_SUSP" = "1" ]; then
    warn "病毒判断：未发现已知挖矿 IOC，但存在可疑启动项，需要人工确认日志。"
  else
    ok "病毒判断：未发现明显已知挖矿 IOC。"
  fi

  if [ "$UPDATE_OK" = "1" ]; then
    ok "Agent 升级：已执行一次原地升级"
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

  out "${B}Nezha Agent 清理 / 排查 / 原地升级${C0}"
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

  scan_ioc
  harden_config
  restart_agent
  update_agent_once

  detect_agent
  harden_config
  restart_agent

  clean_ioc
  security_checks

  scan_ioc
  final_verdict
}

main "$@"
