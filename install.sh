#!/usr/bin/env bash
# nezha-agent-clean-update.sh
#
# 作用：
#   - 自动识别已安装的哪吒 Agent：服务、二进制、配置文件
#   - 不要求你手填 UUID / server / client_secret，直接保留现有配置
#   - 原地下载最新 Agent 二进制替换升级一次
#   - 升级后保留 Agent 自动更新：disable_auto_update=false / disable_force_update=false
#   - 关闭远程命令/在线终端/文件管理能力：disable_command_execute=true
#   - 关闭 NAT 任务：disable_nat=true
#   - 排查并清理常见挖矿木马：xmrig / kinsing / kdevtmpfsi / .kworker / kworker_u8
#
# 用法：
#   bash nezha-agent-clean-update.sh
#
# 可选：
#   NO_UPDATE=1 bash nezha-agent-clean-update.sh       # 不升级，只清理排查加固
#   NO_CLEAN=1 bash nezha-agent-clean-update.sh        # 不清理病毒，只升级加固排查
#   STRICT=1 bash nezha-agent-clean-update.sh          # 额外禁用主动检测任务 disable_send_query=true
#   GH_PROXY='https://ghproxy.net/' bash nezha-agent-clean-update.sh  # GitHub 下载慢时可选
#
# 注意：
#   - 这个脚本只处理 Agent，不会删除 Dashboard 数据库/面板目录/Docker 卷。
#   - 主控机器如果也装了 Agent，也可以执行。
#   - 如果反复出现挖矿进程，建议重装系统并更换 root 密码、SSH key、面板密码、Agent 连接密钥。

set +e
umask 077
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

TS="$(date +%F_%H%M%S)"
LOG="/root/nezha_agent_clean_update_${TS}.log"
QDIR="/root/nezha_quarantine_${TS}"
mkdir -p "$QDIR"

exec > >(tee -a "$LOG") 2>&1

say()  { echo; echo "===== $* ====="; }
info() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*"; }
err()  { echo "[ERROR] $*"; }
has()  { command -v "$1" >/dev/null 2>&1; }

if [ "$(id -u)" -ne 0 ]; then
  err "请用 root 执行"
  exit 1
fi

IOC_REGEX='(/shm/\.kworker|/dev/shm/\.kworker|/run/shm/\.kworker|/tmp/\.kworker|/var/tmp/\.kworker|kworker_u8|kdevtmpfsi|kinsing|xmrig|\.xmrig|kinsingwatch)'
SUSP_REGEX='(/tmp/|/var/tmp/|/dev/shm/|/run/shm/|curl .*\| *sh|wget .*\| *sh|base64[[:space:]]+-d|chmod[[:space:]]+\+x .*/tmp|nohup .*/tmp|python.*http|perl.*http)'

SERVICES=""
SERVICE_ONE=""
UNIT_FILE=""
AGENT_BIN=""
CONFIG_FILE=""

download() {
  local url="$1"
  local out="$2"
  local full_url="${GH_PROXY:-}${url}"

  if has curl; then
    curl -fL --connect-timeout 20 --retry 3 --retry-delay 2 "$full_url" -o "$out"
    return $?
  fi

  if has wget; then
    wget --timeout=25 --tries=3 -O "$out" "$full_url"
    return $?
  fi

  return 127
}

install_pkg_best_effort() {
  local pkg="$1"
  has "$pkg" && return 0

  warn "缺少 $pkg，尝试自动安装"
  if has apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1
    apt-get install -y "$pkg" curl wget ca-certificates >/dev/null 2>&1
  elif has yum; then
    yum install -y "$pkg" curl wget ca-certificates >/dev/null 2>&1
  elif has dnf; then
    dnf install -y "$pkg" curl wget ca-certificates >/dev/null 2>&1
  elif has apk; then
    apk add --no-cache "$pkg" curl wget ca-certificates >/dev/null 2>&1
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
    printf '\n%s: %s\n' "$key" "$val" >> "$file"
  fi
}

detect_service() {
  SERVICES=""

  if has systemctl; then
    SERVICES="$(
      {
        systemctl list-units --type=service --all --no-legend 2>/dev/null | awk '{print $1}' | grep -Ei 'nezha.*agent|nezha-agent' || true
        systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -Ei 'nezha.*agent|nezha-agent' || true
      } | sort -u
    )"
  fi

  SERVICE_ONE=""
  for s in $SERVICES; do
    systemctl cat "$s" >/dev/null 2>&1 && SERVICE_ONE="$s" && break
  done

  if [ -z "$SERVICE_ONE" ] && systemctl cat nezha-agent.service >/dev/null 2>&1; then
    SERVICE_ONE="nezha-agent.service"
  fi
}

detect_from_systemd() {
  [ -n "$SERVICE_ONE" ] || return 0

  UNIT_FILE="$(systemctl show -p FragmentPath --value "$SERVICE_ONE" 2>/dev/null)"

  local catout
  catout="$(systemctl cat "$SERVICE_ONE" 2>/dev/null)"

  local exec_line
  exec_line="$(printf '%s\n' "$catout" | grep -E '^[[:space:]]*ExecStart=' | tail -n1 | sed -E 's/^[[:space:]]*ExecStart=//')"

  if [ -n "$exec_line" ]; then
    # 兼容 ExecStart=/opt/nezha/agent/nezha-agent -c /opt/nezha/agent/config.yml
    AGENT_BIN="$(printf '%s\n' "$exec_line" | awk '{print $1}' | sed 's/^"//; s/"$//')"

    CONFIG_FILE="$(
      printf '%s\n' "$exec_line" | \
      sed -nE 's/.*(^|[[:space:]])-c[[:space:]]+([^[:space:]]+).*/\2/p; s/.*(^|[[:space:]])--config[=[:space:]]+([^[:space:]]+).*/\2/p' | \
      tail -n1 | sed 's/^"//; s/"$//'
    )"
  fi

  if [ -z "$CONFIG_FILE" ]; then
    CONFIG_FILE="$(
      printf '%s\n' "$catout" | grep -Eo '/[^[:space:]]*config[^[:space:]]*\.ya?ml' | head -n1 | sed 's/^"//; s/"$//'
    )"
  fi
}

detect_common_paths() {
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

  if [ -z "$CONFIG_FILE" ] || [ ! -f "$CONFIG_FILE" ]; then
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
        CONFIG_FILE="$p"
        break
      fi
    done
  fi
}

detect_agent() {
  detect_service
  detect_from_systemd
  detect_common_paths
}

agent_version() {
  if [ -x "$AGENT_BIN" ]; then
    "$AGENT_BIN" -v 2>/dev/null || "$AGENT_BIN" --version 2>/dev/null || true
  fi
}

restart_agent() {
  say "重启 Agent"

  if [ -n "$SERVICE_ONE" ] && has systemctl; then
    systemctl daemon-reload 2>/dev/null
    systemctl restart "$SERVICE_ONE" 2>/dev/null
    systemctl status "$SERVICE_ONE" --no-pager -l 2>/dev/null | sed -n '1,30p'
    return 0
  fi

  warn "没有识别到 systemd 服务，无法自动重启。"
  return 1
}

harden_agent_config() {
  say "加固 Agent 配置，保留自动更新"

  if [ -z "$CONFIG_FILE" ] || [ ! -f "$CONFIG_FILE" ]; then
    warn "没找到 Agent 配置文件，跳过配置加固。"
    return 1
  fi

  cp -a "$CONFIG_FILE" "$CONFIG_FILE.bak.${TS}" 2>/dev/null

  yaml_set_bool "$CONFIG_FILE" debug false
  yaml_set_bool "$CONFIG_FILE" disable_command_execute true
  yaml_set_bool "$CONFIG_FILE" disable_nat true
  yaml_set_bool "$CONFIG_FILE" disable_auto_update false
  yaml_set_bool "$CONFIG_FILE" disable_force_update false

  if [ "${STRICT:-0}" = "1" ]; then
    yaml_set_bool "$CONFIG_FILE" disable_send_query true
  fi

  echo "配置文件: $CONFIG_FILE"
  echo "--- 关键配置 ---"
  grep -E '^(debug|disable_command_execute|disable_nat|disable_send_query|disable_auto_update|disable_force_update):' "$CONFIG_FILE" 2>/dev/null || true
}

arch_candidates() {
  case "$(uname -m)" in
    x86_64|amd64)
      echo "amd64"
      ;;
    aarch64|arm64)
      echo "arm64 arm"
      ;;
    armv7l|armv6l|armhf|arm)
      echo "arm"
      ;;
    i386|i686)
      echo "386"
      ;;
    s390x)
      echo "s390x"
      ;;
    riscv64)
      echo "riscv64"
      ;;
    *)
      echo "unknown"
      ;;
  esac
}

update_agent_binary_once() {
  say "自动升级 Agent 一次：保留原配置，仅替换二进制"

  if [ "${NO_UPDATE:-0}" = "1" ]; then
    warn "NO_UPDATE=1，跳过升级。"
    return 0
  fi

  if [ -z "$AGENT_BIN" ] || [ ! -x "$AGENT_BIN" ]; then
    err "没找到 Agent 二进制，无法升级。"
    return 1
  fi

  install_pkg_best_effort unzip || {
    err "缺少 unzip，自动安装失败，无法升级。"
    return 1
  }

  local os
  os="$(uname -s | tr 'A-Z' 'a-z')"
  if [ "$os" != "linux" ]; then
    err "只支持 Linux Agent 自动替换升级。当前: $os"
    return 1
  fi

  local tmpd
  tmpd="$(mktemp -d)"
  local ok="0"
  local zip="$tmpd/nezha-agent.zip"

  for arch in $(arch_candidates); do
    [ "$arch" = "unknown" ] && continue

    local url="https://github.com/nezhahq/agent/releases/latest/download/nezha-agent_${os}_${arch}.zip"
    info "尝试下载: $url"

    if download "$url" "$zip" && [ -s "$zip" ]; then
      unzip -o "$zip" -d "$tmpd/unzip_$arch" >/dev/null 2>&1

      local newbin
      newbin="$(find "$tmpd/unzip_$arch" -type f -name 'nezha-agent' 2>/dev/null | head -n1)"

      if [ -n "$newbin" ]; then
        ok="1"
        info "下载并解压成功: arch=$arch"

        if [ -n "$SERVICE_ONE" ] && has systemctl; then
          systemctl stop "$SERVICE_ONE" 2>/dev/null
        fi

        pkill -f "$AGENT_BIN" 2>/dev/null
        sleep 1

        cp -a "$AGENT_BIN" "$AGENT_BIN.bak.${TS}" 2>/dev/null
        install -m 755 "$newbin" "$AGENT_BIN"

        restart_agent
        break
      fi
    fi
  done

  rm -rf "$tmpd"

  if [ "$ok" != "1" ]; then
    err "自动下载最新 Agent 失败。可能是 GitHub 网络问题，或当前架构没有匹配资产。"
    warn "可以重试：GH_PROXY='https://ghproxy.net/' bash $0"
    return 1
  fi

  echo "--- 升级后版本 ---"
  agent_version
}

quarantine_rm() {
  local f="$1"
  [ -e "$f" ] || return 0

  echo "隔离并删除: $f"
  chattr -i "$f" 2>/dev/null
  cp -a "$f" "$QDIR/" 2>/dev/null
  rm -rf "$f"
}

clean_processes() {
  say "清理已知挖矿进程"

  echo "--- 清理前命中 ---"
  ps auxww | grep -Ei "$IOC_REGEX" | grep -v grep || echo "未发现已知 IOC 进程"

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

    pids="$(pgrep -f "$pat" 2>/dev/null)"
    if [ -n "$pids" ]; then
      echo "发现并终止 $pat: $pids"
      kill $pids 2>/dev/null
      sleep 1
      kill -9 $pids 2>/dev/null
    fi
  done
}

clean_files() {
  say "隔离并删除已知挖矿文件"

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
    quarantine_rm "$f"
  done

  find /tmp /var/tmp /dev/shm /run/shm -maxdepth 2 -xdev 2>/dev/null | \
    grep -Ei '(^|/)(\.kworker.*|kdevtmpfsi|kinsing|xmrig|\.xmrig|kinsingwatch)$' | \
    while read -r f; do
      quarantine_rm "$f"
    done

  rmdir /shm 2>/dev/null
}

clean_file_ioc_lines() {
  local file="$1"
  [ -f "$file" ] || return 0

  if grep -Eiq "$IOC_REGEX" "$file"; then
    echo "清理已知 IOC 行: $file"
    cp -a "$file" "$QDIR/$(echo "$file" | tr '/' '_').bak" 2>/dev/null
    tmpf="$(mktemp)"
    grep -Eiv "$IOC_REGEX" "$file" > "$tmpf"
    cat "$tmpf" > "$file"
    rm -f "$tmpf"
  fi
}

clean_persistence() {
  say "清理 cron/systemd/shell 启动项里的已知 IOC"

  clean_file_ioc_lines /etc/crontab

  for f in \
    /etc/cron.d/* \
    /etc/cron.daily/* \
    /etc/cron.hourly/* \
    /etc/cron.weekly/* \
    /etc/cron.monthly/* \
    /var/spool/cron/* \
    /var/spool/cron/crontabs/*; do
    clean_file_ioc_lines "$f"
  done

  tmpcron="$(mktemp)"
  crontab -l 2>/dev/null > "$tmpcron"
  if grep -Eiq "$IOC_REGEX" "$tmpcron"; then
    echo "清理当前用户 crontab 已知 IOC"
    cp "$tmpcron" "$QDIR/user_crontab.bak" 2>/dev/null
    grep -Eiv "$IOC_REGEX" "$tmpcron" | crontab -
  fi
  rm -f "$tmpcron"

  found_units="$(grep -RIlE "$IOC_REGEX" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null)"
  for f in $found_units; do
    echo "发现可疑 systemd 文件: $f"
    cp -a "$f" "$QDIR/$(echo "$f" | tr '/' '_').bak" 2>/dev/null
    svc="$(basename "$f")"
    systemctl disable --now "$svc" 2>/dev/null
    chattr -i "$f" 2>/dev/null
    mv "$f" "$f.disabled_by_nezha_clean_${TS}" 2>/dev/null
  done

  has systemctl && systemctl daemon-reload 2>/dev/null

  for f in \
    /root/.bashrc \
    /root/.profile \
    /root/.bash_profile \
    /etc/profile \
    /etc/bash.bashrc \
    /etc/profile.d/*; do
    clean_file_ioc_lines "$f"
  done

  if [ -f /etc/ld.so.preload ]; then
    echo "--- /etc/ld.so.preload ---"
    cat /etc/ld.so.preload
    if grep -Eq '/tmp/|/var/tmp/|/dev/shm|/run/shm' /etc/ld.so.preload; then
      echo "ld.so.preload 指向临时目录，已备份并清空"
      cp -a /etc/ld.so.preload "$QDIR/ld.so.preload.bak" 2>/dev/null
      : > /etc/ld.so.preload
    fi
  fi
}

run_checks() {
  say "排查信息"

  echo "--- 最近登录 ---"
  last -ai 2>/dev/null | head -30 || true

  echo
  echo "--- root authorized_keys，请人工确认有没有陌生 key ---"
  if [ -f /root/.ssh/authorized_keys ]; then
    nl -ba /root/.ssh/authorized_keys
  else
    echo "无 /root/.ssh/authorized_keys"
  fi

  for ak in /home/*/.ssh/authorized_keys; do
    [ -f "$ak" ] || continue
    echo
    echo "--- $ak ---"
    nl -ba "$ak"
  done

  echo
  echo "--- 监听端口 ---"
  ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null || true

  echo
  echo "--- CPU Top 20 ---"
  ps auxww --sort=-%cpu | head -20

  echo
  echo "--- MEM Top 20 ---"
  ps auxww --sort=-%mem | head -20

  if has docker; then
    echo
    echo "--- docker ps -a ---"
    docker ps -a 2>/dev/null

    echo
    echo "--- docker images ---"
    docker images 2>/dev/null
  fi

  echo
  echo "--- 仍然可疑的 cron/systemd/shell 行，只展示不删除，请人工确认 ---"
  grep -REin "$SUSP_REGEX|$IOC_REGEX" \
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
    2>/dev/null | head -300 || echo "未发现明显可疑持久化行"
}

final_review() {
  say "最终复查"

  detect_agent

  echo "--- Agent 服务 ---"
  echo "${SERVICE_ONE:-未识别}"

  echo
  echo "--- Agent 二进制 ---"
  echo "${AGENT_BIN:-未识别}"

  echo
  echo "--- Agent 配置 ---"
  echo "${CONFIG_FILE:-未识别}"

  echo
  echo "--- Agent 版本 ---"
  agent_version

  echo
  echo "--- 关键配置 ---"
  if [ -f "$CONFIG_FILE" ]; then
    grep -E '^(debug|disable_command_execute|disable_nat|disable_send_query|disable_auto_update|disable_force_update):' "$CONFIG_FILE" 2>/dev/null || true
  fi

  echo
  echo "--- IOC 进程复查 ---"
  ps auxww | grep -Ei "$IOC_REGEX" | grep -v grep || echo "未发现已知 IOC 进程"

  echo
  echo "--- IOC 自启动复查 ---"
  grep -REin "$IOC_REGEX" \
    /etc/cron* \
    /var/spool/cron* \
    /etc/systemd/system \
    /lib/systemd/system \
    /usr/lib/systemd/system \
    /root \
    2>/dev/null | head -200 || echo "未发现已知 IOC 自启动残留"

  echo
  echo "日志文件: $LOG"
  echo "隔离目录: $QDIR"
}

main() {
  say "基本信息"
  date
  hostname 2>/dev/null || true
  uname -a
  [ -f /etc/os-release ] && sed -n '1,10p' /etc/os-release

  say "识别哪吒 Agent"
  detect_agent
  echo "服务: ${SERVICE_ONE:-未识别}"
  echo "Unit: ${UNIT_FILE:-未识别}"
  echo "二进制: ${AGENT_BIN:-未识别}"
  echo "配置: ${CONFIG_FILE:-未识别}"
  echo "--- 升级前版本 ---"
  agent_version

  harden_agent_config
  restart_agent

  update_agent_binary_once

  detect_agent
  harden_agent_config
  restart_agent

  if [ "${NO_CLEAN:-0}" != "1" ]; then
    clean_processes
    clean_files
    clean_persistence
  else
    warn "NO_CLEAN=1，跳过清理。"
  fi

  run_checks
  final_review

  say "完成"
  echo "这个脚本已经：排查/清理常见挖矿 IOC、原地升级 Agent 一次、关闭远程命令能力、保留自动更新。"
  echo "如果病毒反复出现，建议重装系统并更换 root 密码、SSH key、面板密码、Agent 连接密钥。"
}

main "$@"
