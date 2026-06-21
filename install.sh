#!/usr/bin/env bash
# install.sh
# Nezha Agent 纯探针加固 + systemd 权限隔离 + 常见挖矿/对外攻击 IOC 扫描清理
#
# 默认策略：
#   [01] 开启：保留基础监控上报
#   [02] 开启：保留 Agent 自己自动更新
#   [03] 开启：保留 HTTP/TCP/ICMP 主动探测权限
#   [04] 关闭：远程命令权限
#   [05] 关闭：在线终端权限
#   [06] 关闭：文件管理权限
#   [07] 关闭：远程配置/任务控制权限
#   [08] 关闭：NAT 内网穿透权限
#   [09] 关闭：面板强制更新权限
#   [10] 开启：systemd 权限隔离
#   [11] 开启：执行一次 Agent 原地升级
#   [12] 开启：扫描并自动清理高置信挖矿/对外攻击 IOC
#
# 默认最终配置：
#   disable_command_execute: true
#   disable_nat: true
#   disable_send_query: false
#   disable_auto_update: false
#   disable_force_update: true
#
# 用法：
#   bash <(curl -fsSL https://raw.githubusercontent.com/inimemail/nagen/main/install.sh)
#
# 非交互全部用默认：
#   NONINTERACTIVE=1 bash <(curl -fsSL https://raw.githubusercontent.com/inimemail/nagen/main/install.sh)
#
# 可选：
#   NO_UPDATE=1        不执行第 11 项原地升级
#   DO_UPDATE=0        同上
#   NO_IOC=1           不执行第 12 项 IOC 扫描清理
#   NO_SANDBOX=1       不执行第 10 项 systemd 隔离
#   GH_PROXY='https://ghfast.top/'   GitHub 下载慢时使用
#
# 说明：
#   - 不需要填写 UUID / server / client_secret，会保留现有配置。
#   - Agent 自己自动更新保留：disable_auto_update=false。
#   - 面板强制更新默认关闭：disable_force_update=true。
#   - systemd 隔离默认允许 Agent 目录写入，所以不影响 Agent 自己自动更新。
#   - 不再创建/写入日志文件，只在屏幕输出必要结果。
#   - 高置信 IOC 才自动清理，尽量避免误报。

set +e
umask 077
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

TS="$(date +%F_%H%M%S)"
QDIR=""
SCAN_TMP="$(mktemp -d /tmp/nezha_scan.XXXXXX 2>/dev/null || mktemp -d)"
cleanup_tmp() {
  [ -n "${SCAN_TMP:-}" ] && rm -rf "$SCAN_TMP" >/dev/null 2>&1
}
trap cleanup_tmp EXIT
ensure_qdir() {
  if [ -z "${QDIR:-}" ]; then
    QDIR="/root/nezha_pure_probe_quarantine_${TS}"
    mkdir -p "$QDIR"
  fi
}

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

out()   { printf "%b\n" "$*"; }
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

ask_yn() {
  # ask_yn "01/12" "标题" "默认 Y/N"
  local no="$1"
  local title_text="$2"
  local def="$3"
  local ans def_word

  if [ "$def" = "Y" ]; then
    def_word="开启"
  else
    def_word="关闭"
  fi

  if [ "${NONINTERACTIVE:-0}" = "1" ]; then
    info "[${no}] ${title_text} -> 默认${def_word}"
    [ "$def" = "Y" ]
    return $?
  fi

  while true; do
    printf "%b" "${B}[${no}]${C0} ${title_text}（默认${def_word}，回车确认）："
    read -r ans

    if [ -z "$ans" ]; then
      [ "$def" = "Y" ]
      return $?
    fi

    case "$ans" in
      y|Y|yes|YES|Yes|1|on|ON|是|开启|开|保留|允许)
        return 0
        ;;
      n|N|no|NO|No|0|off|OFF|否|不|不开|跳过|关闭|禁止)
        return 1
        ;;
      *)
        out "${YELLOW}输入无效：请输入 y=开启 / n=关闭 / 回车=默认。${C0}"
        ;;
    esac
  done
}

download() {
  local url="$1"
  local dst="$2"
  local final_url="${GH_PROXY:-}${url}"

  if has curl; then
    curl -fL --connect-timeout 20 --retry 3 --retry-delay 2 "$final_url" -o "$dst" >/dev/null 2>&1
    return $?
  fi

  if has wget; then
    wget --timeout=25 --tries=3 -O "$dst" "$final_url" >/dev/null 2>&1
    return $?
  fi

  return 127
}

install_pkg() {
  local pkg="$1"
  has "$pkg" && return 0

  warn "缺少 $pkg，尝试自动安装"
  if has apt-get; then
    DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" curl wget ca-certificates >/dev/null 2>&1
  elif has yum; then
    yum install -y "$pkg" curl wget ca-certificates >/dev/null 2>&1
  elif has dnf; then
    dnf install -y "$pkg" curl wget ca-certificates >/dev/null 2>&1
  elif has apk; then
    apk add --no-cache "$pkg" curl wget ca-certificates >/dev/null 2>&1
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

SERVICE=""
UNIT=""
AGENT_BIN=""
CONFIG=""

KEEP_REPORT=1
KEEP_AUTO_UPDATE=1
CLOSE_QUERY=0
CLOSE_REMOTE_TASKS=1
CLOSE_NAT=1
CLOSE_FORCE_UPDATE=1
ENABLE_SANDBOX=1
DO_IOC=1
DO_UPDATE=1

if [ "${NO_UPDATE:-0}" = "1" ]; then
  DO_UPDATE=0
fi
if [ "${DO_UPDATE:-1}" = "0" ]; then
  DO_UPDATE=0
fi

FOUND_HIGH_IOC=0
FOUND_REVIEW=0
FOUND_LOW=0
UPDATE_OK=0
UPDATE_FAIL=0
CONFIG_OK=0
SANDBOX_OK=0
CONFIG_BACKED_UP=0

HIT_PROC="$SCAN_TMP/high_ioc_process.txt"
HIT_FILE="$SCAN_TMP/high_ioc_file.txt"
HIT_PERSIST="$SCAN_TMP/high_ioc_persist.txt"
HIT_REVIEW="$SCAN_TMP/review_suspicious.txt"
HIT_LOW="$SCAN_TMP/low_cron_comment.txt"
HIT_NET="$SCAN_TMP/high_ioc_network.txt"
HIT_PIDS="$SCAN_TMP/high_ioc_pids.txt"

# 高置信 IOC：只命中这些才自动清理。
# 范围：常见挖矿、Kinsing/kdevtmpfsi/XMRig、Sysrv、perfctl、Mirai/Gafgyt/Mozi/Muhstik、常见扫描器/爆破工具等。
IOC_LINE_REGEX='(/shm/\.kworker|/dev/shm/\.kworker|/run/shm/\.kworker|/tmp/\.kworker|/var/tmp/\.kworker|/(tmp|var/tmp|dev/shm|run/shm)/[^[:space:]]*(kdevtmpfsi|kinsing|kinsingwatch|xmrig|\.xmrig|xmr-stak|sysrv|sysrv-hello|perfctl|pnscan|masscan|zmap|zgrab|mirai|gafgyt|mozi|muhstik|tsunami|bashirc|dota3|dbused|\.javae|\.syst3md|\.systemd|\.httpd|\.sshd|\.watchdog|watchdogs)|(^|[[:space:]])(kworker_u8|kdevtmpfsi|kinsing|kinsingwatch|xmrig|xmrig-notls|xmr-stak|sysrv|sysrv-hello|perfctl|pnscan|masscan|zmap|zgrab|mirai|gafgyt|mozi|muhstik|tsunami|bashirc|dota3|dbused)([[:space:]]|$)|stratum\+tcp|pool\.[^[:space:]]*xmr|monero|cryptonight|nicehash)'

HIGH_PROC_NAME_REGEX='(kworker_u8|kdevtmpfsi|kinsing|kinsingwatch|xmrig|xmrig-notls|xmr-stak|sysrv|sysrv-hello|perfctl|pnscan|masscan|zmap|zgrab|mirai|gafgyt|mozi|muhstik|tsunami|bashirc|dota3|dbused)'
HIGH_TMP_NAME_REGEX='(\.kworker.*|kdevtmpfsi|kinsing|kinsingwatch|xmrig|\.xmrig|xmr-stak|sysrv.*|perfctl|pnscan|masscan|zmap|zgrab|mirai|gafgyt|mozi|muhstik|tsunami|bashirc|dota3|dbused|\.javae|\.syst3md|\.systemd|\.httpd|\.sshd|\.watchdogs?|watchdogs?)'
MINER_PORT_REGEX=':(3333|3334|3335|4444|5555|5556|6666|7777|7778|8888|9999|14433|14444|45700|55555)([[:space:]]|$)'

# 中风险：只提示，不自动删
REVIEW_LINE_REGEX='(curl[[:space:]].*\|[[:space:]]*(sh|bash)|wget[[:space:]].*\|[[:space:]]*(sh|bash)|base64[[:space:]]+-d|chmod[[:space:]]+\+x[[:space:]]+/(tmp|var/tmp|dev/shm|run/shm)|nohup[[:space:]]+/(tmp|var/tmp|dev/shm|run/shm)|/(tmp|var/tmp|dev/shm|run/shm)/[^[:space:]]+[[:space:]]*(&|$)|bash[[:space:]]+-c[[:space:]].*/(tmp|var/tmp|dev/shm|run/shm)|python[0-9.]*[[:space:]].*(socket|subprocess|base64)|perl[[:space:]].*(socket|IO::Socket)|nc[[:space:]]+.*-e|ncat[[:space:]]+.*-e|socat[[:space:]].*EXEC:)'

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
    local catout exec_line

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
    systemctl daemon-reload >/dev/null 2>&1
    systemctl restart "$SERVICE" >/dev/null 2>&1
    sleep 1

    if systemctl is-active --quiet "$SERVICE"; then
      ok "Agent 已重启"
      return 0
    fi

    warn "Agent 重启后不是 active，请手动执行 systemctl status 查看"
    systemctl status "$SERVICE" --no-pager -l >/dev/null 2>&1
    return 1
  fi

  warn "未识别到 systemd 服务，跳过自动重启"
  return 1
}

ask_options() {
  title "纯探针权限配置"
  out "${DIM}默认规则：01、02、03、10、11、12 开启；04-09 关闭。一路回车即可。${C0}"
  out "${DIM}04-07 是权限项。默认关闭 = 不允许面板远程控制。${C0}"
  out ""

  if ask_yn "01/12" "保留基础监控上报" "Y"; then KEEP_REPORT=1; else KEEP_REPORT=0; fi
  if ask_yn "02/12" "保留 Agent 自己自动更新" "Y"; then KEEP_AUTO_UPDATE=1; else KEEP_AUTO_UPDATE=0; fi
  if ask_yn "03/12" "HTTP/TCP/ICMP 主动探测权限" "Y"; then CLOSE_QUERY=0; else CLOSE_QUERY=1; fi

  if ask_yn "04/12" "远程命令权限" "N"; then allow_cmd=1; else allow_cmd=0; fi
  if ask_yn "05/12" "在线终端权限" "N"; then allow_terminal=1; else allow_terminal=0; fi
  if ask_yn "06/12" "文件管理权限" "N"; then allow_file=1; else allow_file=0; fi
  if ask_yn "07/12" "远程配置/任务控制权限" "N"; then allow_config=1; else allow_config=0; fi

  if [ "$allow_cmd" = "1" ] || [ "$allow_terminal" = "1" ] || [ "$allow_file" = "1" ] || [ "$allow_config" = "1" ]; then
    CLOSE_REMOTE_TASKS=0
    warn "你开启了 04-07 中至少一项。由于官方是同一个开关，整组远程控制能力会开启。"
  else
    CLOSE_REMOTE_TASKS=1
  fi

  if ask_yn "08/12" "NAT 内网穿透权限" "N"; then CLOSE_NAT=0; else CLOSE_NAT=1; fi
  if ask_yn "09/12" "面板强制更新权限" "N"; then CLOSE_FORCE_UPDATE=0; else CLOSE_FORCE_UPDATE=1; fi

  if [ "${NO_SANDBOX:-0}" = "1" ]; then
    ENABLE_SANDBOX=0
    warn "NO_SANDBOX=1：跳过 systemd 隔离"
  else
    if ask_yn "10/12" "开启 systemd 权限隔离" "Y"; then ENABLE_SANDBOX=1; else ENABLE_SANDBOX=0; fi
  fi

  if [ "$DO_UPDATE" = "1" ]; then
    if ask_yn "11/12" "现在执行一次 Agent 原地升级" "Y"; then DO_UPDATE=1; else DO_UPDATE=0; fi
  else
    if ask_yn "11/12" "现在执行一次 Agent 原地升级" "N"; then DO_UPDATE=1; else DO_UPDATE=0; fi
  fi

  if [ "${NO_IOC:-0}" = "1" ]; then
    DO_IOC=0
    warn "NO_IOC=1：跳过 IOC 扫描清理"
  else
    if ask_yn "12/12" "扫描并自动清理高置信挖矿/对外攻击 IOC" "Y"; then DO_IOC=1; else DO_IOC=0; fi
  fi

  out ""
}

apply_config() {
  title "写入 Agent 纯探针配置"

  if [ -z "$CONFIG" ] || [ ! -f "$CONFIG" ]; then
    bad "未找到 Agent 配置文件，无法写入配置"
    return 1
  fi

  if [ "$CONFIG_BACKED_UP" != "1" ]; then
    cp -a "$CONFIG" "$CONFIG.bak.pure_probe" 2>/dev/null
    CONFIG_BACKED_UP=1
  fi

  if [ "$KEEP_REPORT" = "0" ]; then
    warn "你选择不保留基础上报，这等于停止 Agent。"
    if ask_yn "CONFIRM" "确认停止并禁用 nezha-agent" "N"; then
      systemctl disable --now "$SERVICE" >/dev/null 2>&1
      ok "Agent 已停止并禁用"
      exit 0
    else
      KEEP_REPORT=1
      warn "已取消停止 Agent，继续保留基础监控上报"
    fi
  fi

  yaml_set_bool "$CONFIG" debug false

  if [ "$CLOSE_REMOTE_TASKS" = "1" ]; then
    yaml_set_bool "$CONFIG" disable_command_execute true
  else
    yaml_set_bool "$CONFIG" disable_command_execute false
  fi

  if [ "$CLOSE_NAT" = "1" ]; then
    yaml_set_bool "$CONFIG" disable_nat true
  else
    yaml_set_bool "$CONFIG" disable_nat false
  fi

  if [ "$CLOSE_QUERY" = "1" ]; then
    yaml_set_bool "$CONFIG" disable_send_query true
  else
    yaml_set_bool "$CONFIG" disable_send_query false
  fi

  if [ "$KEEP_AUTO_UPDATE" = "1" ]; then
    yaml_set_bool "$CONFIG" disable_auto_update false
  else
    yaml_set_bool "$CONFIG" disable_auto_update true
  fi

  if [ "$CLOSE_FORCE_UPDATE" = "1" ]; then
    yaml_set_bool "$CONFIG" disable_force_update true
  else
    yaml_set_bool "$CONFIG" disable_force_update false
  fi

  CONFIG_OK=1
  ok "配置已写入"
  info "配置备份：$CONFIG.bak.pure_probe（固定覆盖，不堆文件）"

  {
    echo
    echo "--- pure probe config ---"
    grep -E '^(debug|disable_command_execute|disable_nat|disable_send_query|disable_auto_update|disable_force_update):' "$CONFIG" 2>/dev/null || true
  } >/dev/null
}

apply_systemd_sandbox() {
  title "写入 systemd 权限隔离"

  if [ "$ENABLE_SANDBOX" != "1" ]; then
    warn "跳过 systemd 隔离"
    return 0
  fi

  if [ -z "$SERVICE" ] || ! has systemctl; then
    warn "未识别到 systemd 服务，无法写入隔离"
    return 1
  fi

  local agent_dir cfg_dir dropin
  agent_dir="$(dirname "$AGENT_BIN" 2>/dev/null)"
  cfg_dir="$(dirname "$CONFIG" 2>/dev/null)"

  [ -z "$agent_dir" ] && agent_dir="/opt/nezha/agent"
  [ -z "$cfg_dir" ] && cfg_dir="$agent_dir"

  dropin="/etc/systemd/system/${SERVICE}.d"
  mkdir -p "$dropin"

  cat > "$dropin/10-pure-probe-hardening.conf" <<EOF
[Service]
# Pure-probe hardening generated by install.sh
# 保持原服务用户，不强制改 User，避免影响基础监控和自动更新。
# 兼容 Agent 自动更新：允许 Agent 目录和配置目录写入。
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ProtectHostname=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=${agent_dir} ${cfg_dir}
EOF

  systemctl daemon-reload >/dev/null 2>&1
  SANDBOX_OK=1
  ok "systemd 隔离已写入：$dropin/10-pure-probe-hardening.conf"
  info "自动更新兼容：允许写入 ${agent_dir}"
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
  title "Agent 原地升级"

  if [ "$DO_UPDATE" != "1" ]; then
    warn "跳过原地升级"
    return 0
  fi

  if [ -z "$AGENT_BIN" ] || [ ! -x "$AGENT_BIN" ]; then
    bad "未找到 Agent 二进制，无法升级"
    UPDATE_FAIL=1
    return 1
  fi

  install_pkg unzip >/dev/null 2>&1
  if ! has unzip; then
    bad "缺少 unzip，自动安装失败，无法升级"
    UPDATE_FAIL=1
    return 1
  fi

  local os before tmpd zip ok_arch newbin
  os="$(uname -s | tr 'A-Z' 'a-z')"

  if [ "$os" != "linux" ]; then
    bad "当前系统不是 Linux，跳过升级"
    UPDATE_FAIL=1
    return 1
  fi

  before="$(agent_version "$AGENT_BIN" | head -n1)"
  [ -n "$before" ] && info "升级前：$before"

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
      unzip -o "$zip" -d "$tmpd/unzip_$arch" >/dev/null 2>&1
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

  [ -n "$SERVICE" ] && systemctl stop "$SERVICE" >/dev/null 2>&1
  pkill -f "$AGENT_BIN" >/dev/null 2>&1
  sleep 1

  cp -a "$AGENT_BIN" "$AGENT_BIN.bak.pure_probe" 2>/dev/null
  install -m 755 "$newbin" "$AGENT_BIN" >/dev/null 2>&1
  local rc=$?
  rm -rf "$tmpd"

  if [ "$rc" -ne 0 ]; then
    bad "替换 Agent 二进制失败"
    UPDATE_FAIL=1
    restart_agent
    return 1
  fi

  UPDATE_OK=1
  ok "已替换 Agent 二进制：$ok_arch"
  info "旧二进制备份：$AGENT_BIN.bak.pure_probe（固定覆盖，不堆文件）"

  restart_agent

  local after
  after="$(agent_version "$AGENT_BIN" | head -n1)"
  [ -n "$after" ] && info "升级后：$after"
}

scan_high_ioc_process() {
  : > "$HIT_PROC"
  : > "$HIT_PIDS"

  ps auxww | awk '
    BEGIN { IGNORECASE=1 }
    {
      line=$0
      if (line ~ /\[kworker\//) next
      if (line ~ /\[kdevtmpfs\]/) next

      if (
        line ~ /\/(tmp|var\/tmp|dev\/shm|run\/shm)\/[^[:space:]]*(\.kworker|kdevtmpfsi|kinsing|kinsingwatch|xmrig|\.xmrig|xmr-stak|sysrv|perfctl|pnscan|masscan|zmap|zgrab|mirai|gafgyt|mozi|muhstik|tsunami|bashirc|dota3|dbused|\.javae|\.syst3md|\.systemd|\.httpd|\.sshd|\.watchdog|watchdogs)/ ||
        line ~ /(^|[[:space:]])(kworker_u8|kdevtmpfsi|kinsing|kinsingwatch|xmrig|xmrig-notls|xmr-stak|sysrv|sysrv-hello|perfctl|pnscan|masscan|zmap|zgrab|mirai|gafgyt|mozi|muhstik|tsunami|bashirc|dota3|dbused)([[:space:]]|$)/ ||
        line ~ /stratum\+tcp|pool\.[^[:space:]]*xmr|monero|cryptonight|nicehash/
      ) print line
    }
  ' > "$HIT_PROC" 2>/dev/null

  if [ -s "$HIT_PROC" ]; then
    awk '{print $2}' "$HIT_PROC" | grep -E '^[0-9]+$' >> "$HIT_PIDS" 2>/dev/null
    sort -u "$HIT_PIDS" -o "$HIT_PIDS" 2>/dev/null
    FOUND_HIGH_IOC=1
    bad "发现高置信挖矿/对外攻击进程"
    out ""
    out "${B}命中进程：${C0}"
    head -30 "$HIT_PROC"
  else
    ok "未发现高置信挖矿/对外攻击进程"
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
    /tmp/kdevtmpfsi* \
    /var/tmp/kdevtmpfsi* \
    /dev/shm/kdevtmpfsi* \
    /run/shm/kdevtmpfsi* \
    /tmp/kinsing* \
    /var/tmp/kinsing* \
    /dev/shm/kinsing* \
    /run/shm/kinsing* \
    /tmp/xmrig* \
    /var/tmp/xmrig* \
    /dev/shm/xmrig* \
    /run/shm/xmrig* \
    /tmp/.xmrig* \
    /var/tmp/.xmrig* \
    /dev/shm/.xmrig* \
    /run/shm/.xmrig* \
    /tmp/kinsingwatch* \
    /var/tmp/kinsingwatch* \
    /tmp/sysrv* \
    /var/tmp/sysrv* \
    /dev/shm/sysrv* \
    /run/shm/sysrv* \
    /tmp/perfctl* \
    /var/tmp/perfctl* \
    /dev/shm/perfctl* \
    /run/shm/perfctl* \
    /tmp/pnscan* \
    /var/tmp/pnscan* \
    /dev/shm/pnscan* \
    /run/shm/pnscan* \
    /tmp/masscan* \
    /var/tmp/masscan* \
    /dev/shm/masscan* \
    /run/shm/masscan* \
    /tmp/zmap* \
    /var/tmp/zmap* \
    /dev/shm/zmap* \
    /run/shm/zmap* \
    /tmp/zgrab* \
    /var/tmp/zgrab* \
    /dev/shm/zgrab* \
    /run/shm/zgrab* \
    /tmp/mirai* \
    /var/tmp/mirai* \
    /dev/shm/mirai* \
    /run/shm/mirai* \
    /tmp/gafgyt* \
    /var/tmp/gafgyt* \
    /dev/shm/gafgyt* \
    /run/shm/gafgyt* \
    /tmp/mozi* \
    /var/tmp/mozi* \
    /dev/shm/mozi* \
    /run/shm/mozi* \
    /tmp/muhstik* \
    /var/tmp/muhstik* \
    /dev/shm/muhstik* \
    /run/shm/muhstik* \
    /tmp/tsunami* \
    /var/tmp/tsunami* \
    /dev/shm/tsunami* \
    /run/shm/tsunami* \
    /tmp/bashirc* \
    /var/tmp/bashirc* \
    /dev/shm/bashirc* \
    /run/shm/bashirc* \
    /tmp/dota3* \
    /var/tmp/dota3* \
    /dev/shm/dota3* \
    /run/shm/dota3* \
    /tmp/dbused* \
    /var/tmp/dbused* \
    /dev/shm/dbused* \
    /run/shm/dbused* \
    /tmp/.javae* \
    /var/tmp/.javae* \
    /dev/shm/.javae* \
    /run/shm/.javae* \
    /tmp/.syst3md* \
    /var/tmp/.syst3md* \
    /dev/shm/.syst3md* \
    /run/shm/.syst3md* \
    /tmp/.systemd* \
    /var/tmp/.systemd* \
    /dev/shm/.systemd* \
    /run/shm/.systemd* \
    /tmp/.httpd* \
    /var/tmp/.httpd* \
    /dev/shm/.httpd* \
    /run/shm/.httpd* \
    /tmp/.sshd* \
    /var/tmp/.sshd* \
    /dev/shm/.sshd* \
    /run/shm/.sshd* \
    /tmp/.watchdog* \
    /var/tmp/.watchdog* \
    /dev/shm/.watchdog* \
    /run/shm/.watchdog*; do
    [ -e "$f" ] && printf "%s\n" "$f" >> "$HIT_FILE"
  done

  find /tmp /var/tmp /dev/shm /run/shm -maxdepth 3 -xdev 2>/dev/null | \
    grep -Ei "(^|/)${HIGH_TMP_NAME_REGEX}$" >> "$HIT_FILE" 2>/dev/null

  sort -u "$HIT_FILE" -o "$HIT_FILE" 2>/dev/null

  if [ -s "$HIT_FILE" ]; then
    FOUND_HIGH_IOC=1
    bad "发现高置信挖矿/对外攻击文件"
    out ""
    out "${B}命中文件：${C0}"
    head -50 "$HIT_FILE"
  else
    ok "未发现高置信挖矿/对外攻击文件"
  fi
}

proc_is_tmp_or_bad() {
  local pid="$1"
  local exe cmd comm blob

  [ -n "$pid" ] || return 1
  [ -d "/proc/$pid" ] || return 1

  exe="$(readlink "/proc/$pid/exe" 2>/dev/null)"
  cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
  comm="$(cat "/proc/$pid/comm" 2>/dev/null)"
  blob="$exe $cmd $comm"

  printf "%s\n" "$blob" | grep -Eiq "$HIGH_PROC_NAME_REGEX" && return 0
  printf "%s\n" "$blob" | grep -Eiq "$IOC_LINE_REGEX" && return 0
  printf "%s\n" "$exe $cmd" | grep -Eiq '(^|[[:space:]])/(tmp|var/tmp|dev/shm|run/shm)/' && return 0

  return 1
}

scan_high_ioc_network() {
  : > "$HIT_NET"

  local netout line pidlist pid hit
  if has ss; then
    netout="$(ss -Htanp 2>/dev/null)"
  elif has netstat; then
    netout="$(netstat -tanp 2>/dev/null)"
  else
    ok "未安装 ss/netstat，跳过外联连接扫描"
    return 0
  fi

  while IFS= read -r line; do
    [ -n "$line" ] || continue
    hit=0
    pidlist="$(printf "%s\n" "$line" | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)"

    # 进程名直接命中挖矿/扫描器/僵尸网络工具。
    if printf "%s\n" "$line" | grep -Eiq "$HIGH_PROC_NAME_REGEX"; then
      hit=1
    fi

    # 矿池端口命中时，再要求 PID 对应进程也可疑，避免误杀正常 8888/9999 服务。
    if [ "$hit" = "0" ] && printf "%s\n" "$line" | grep -Eiq "$MINER_PORT_REGEX"; then
      for pid in $pidlist; do
        if proc_is_tmp_or_bad "$pid"; then
          hit=1
          break
        fi
      done
    fi

    if [ "$hit" = "1" ]; then
      printf "%s\n" "$line" >> "$HIT_NET"
      for pid in $pidlist; do
        [ -n "$pid" ] && printf "%s\n" "$pid" >> "$HIT_PIDS"
      done
    fi
  done <<EOF_NET
$netout
EOF_NET

  sort -u "$HIT_PIDS" -o "$HIT_PIDS" 2>/dev/null

  if [ -s "$HIT_NET" ]; then
    FOUND_HIGH_IOC=1
    bad "发现高置信挖矿/对外攻击外联"
    out ""
    out "${B}命中外联：${C0}"
    head -40 "$HIT_NET"
  else
    ok "未发现高置信挖矿/对外攻击外联"
  fi
}

scan_persistence() {
  : > "$HIT_PERSIST"
  : > "$HIT_REVIEW"
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

  grep -REin "$IOC_LINE_REGEX" $targets 2>/dev/null | \
    grep -Ev '^[^:]+:[0-9]+:[[:space:]]*#' > "$HIT_PERSIST"

  grep -REin "$REVIEW_LINE_REGEX" $targets 2>/dev/null | \
    grep -Ev '^[^:]+:[0-9]+:[[:space:]]*#' > "$HIT_REVIEW"

  grep -REin '^# \(/tmp/tmp\.[^)]* installed on ' /var/spool/cron /var/spool/cron/crontabs 2>/dev/null > "$HIT_LOW"

  if [ -s "$HIT_PERSIST" ]; then
    FOUND_HIGH_IOC=1
    bad "发现高置信挖矿自启动"
    out ""
    out "${B}命中自启动：${C0}"
    head -30 "$HIT_PERSIST"
  else
    ok "未发现高置信挖矿自启动"
  fi

  if [ -s "$HIT_REVIEW" ]; then
    FOUND_REVIEW=1
    warn "发现中风险可疑启动项，只提示不自动删除"
    out ""
    out "${B}中风险可疑项：${C0}"
    head -20 "$HIT_REVIEW"
  else
    ok "未发现中风险可疑启动项"
  fi

  if [ -s "$HIT_LOW" ]; then
    FOUND_LOW=1
    warn "发现 crontab 临时文件注释，低风险，稍后清理误报"
    out ""
    out "${B}低风险注释：${C0}"
    head -10 "$HIT_LOW"
  fi
}

scan_context_brief() {
  # 默认不打印端口/CPU 表格，避免输出太乱。
  # 如需排查，手动执行：ss -lntup 或 ps auxww --sort=-%cpu | head
  return 0
}

scan_ioc() {
  title "高置信挖矿/对外攻击 IOC 扫描"
  scan_high_ioc_process
  scan_high_ioc_network
  scan_high_ioc_files
  scan_persistence
  scan_context_brief
  info "扫描完成：无日志、无快照表格、无命中则不创建隔离目录"
}

kill_one_pid() {
  local pid="$1"
  [ -n "$pid" ] || return 1
  [ "$pid" = "$$" ] && return 1
  [ "$pid" = "$PPID" ] && return 1
  [ ! -d "/proc/$pid" ] && return 1

  kill "$pid" >/dev/null 2>&1
  sleep 1
  kill -9 "$pid" >/dev/null 2>&1
  return 0
}

kill_ioc_processes() {
  local killed=0
  local pat pids pid

  # 先杀网络扫描阶段提取到的可疑 PID。
  if [ -s "$HIT_PIDS" ]; then
    while IFS= read -r pid; do
      if kill_one_pid "$pid"; then
        killed=1
      fi
    done < "$HIT_PIDS"
  fi

  # 再按高置信名称/路径兜底杀一次。
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
    '/tmp/sysrv' \
    '/var/tmp/sysrv' \
    '/dev/shm/sysrv' \
    '/run/shm/sysrv' \
    '/tmp/perfctl' \
    '/var/tmp/perfctl' \
    '/dev/shm/perfctl' \
    '/run/shm/perfctl' \
    '/tmp/pnscan' \
    '/var/tmp/pnscan' \
    '/dev/shm/pnscan' \
    '/run/shm/pnscan' \
    '/tmp/masscan' \
    '/var/tmp/masscan' \
    '/dev/shm/masscan' \
    '/run/shm/masscan' \
    '/tmp/zmap' \
    '/var/tmp/zmap' \
    '/dev/shm/zmap' \
    '/run/shm/zmap' \
    '/tmp/zgrab' \
    '/var/tmp/zgrab' \
    '/dev/shm/zgrab' \
    '/run/shm/zgrab' \
    '/tmp/mirai' \
    '/var/tmp/mirai' \
    '/dev/shm/mirai' \
    '/run/shm/mirai' \
    '/tmp/gafgyt' \
    '/var/tmp/gafgyt' \
    '/dev/shm/gafgyt' \
    '/run/shm/gafgyt' \
    '/tmp/mozi' \
    '/var/tmp/mozi' \
    '/dev/shm/mozi' \
    '/run/shm/mozi' \
    '/tmp/muhstik' \
    '/var/tmp/muhstik' \
    '/dev/shm/muhstik' \
    '/run/shm/muhstik' \
    '/tmp/tsunami' \
    '/var/tmp/tsunami' \
    '/dev/shm/tsunami' \
    '/run/shm/tsunami' \
    '/tmp/bashirc' \
    '/var/tmp/bashirc' \
    '/dev/shm/bashirc' \
    '/run/shm/bashirc' \
    '/tmp/dota3' \
    '/var/tmp/dota3' \
    '/dev/shm/dota3' \
    '/run/shm/dota3' \
    '/tmp/dbused' \
    '/var/tmp/dbused' \
    '/dev/shm/dbused' \
    '/run/shm/dbused' \
    '/tmp/.javae' \
    '/var/tmp/.javae' \
    '/dev/shm/.javae' \
    '/run/shm/.javae' \
    '/tmp/.syst3md' \
    '/var/tmp/.syst3md' \
    '/dev/shm/.syst3md' \
    '/run/shm/.syst3md' \
    '/tmp/.systemd' \
    '/var/tmp/.systemd' \
    '/dev/shm/.systemd' \
    '/run/shm/.systemd' \
    '/tmp/.httpd' \
    '/var/tmp/.httpd' \
    '/dev/shm/.httpd' \
    '/run/shm/.httpd' \
    '/tmp/.sshd' \
    '/var/tmp/.sshd' \
    '/dev/shm/.sshd' \
    '/run/shm/.sshd' \
    'kworker_u8' \
    'kdevtmpfsi' \
    'kinsing' \
    'kinsingwatch' \
    'xmrig' \
    'xmrig-notls' \
    'xmr-stak' \
    'sysrv' \
    'sysrv-hello' \
    'perfctl' \
    'pnscan' \
    'masscan' \
    'zmap' \
    'zgrab' \
    'mirai' \
    'gafgyt' \
    'mozi' \
    'muhstik' \
    'tsunami' \
    'bashirc' \
    'dota3' \
    'dbused'; do
    pids="$(pgrep -f "$pat" 2>/dev/null)"

    if [ -n "$pids" ]; then
      for pid in $pids; do
        if kill_one_pid "$pid"; then
          killed=1
        fi
      done
    fi
  done

  [ "$killed" = "1" ] && ok "已终止高置信挖矿/对外攻击进程" || ok "无需终止挖矿/对外攻击进程"
}

quarantine_rm() {
  local f="$1"
  [ -e "$f" ] || return 0

  ensure_qdir
  chattr -i "$f" >/dev/null 2>&1
  cp -a "$f" "$QDIR/" >/dev/null 2>&1
  rm -rf "$f" >/dev/null 2>&1
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

  rmdir /shm >/dev/null 2>&1
  [ "$removed" = "1" ] && ok "已隔离删除高置信挖矿文件" || ok "无需删除挖矿文件"
}

clean_ioc_line_in_file() {
  local file="$1"
  [ -f "$file" ] || return 0

  if grep -Eiq "$IOC_LINE_REGEX" "$file"; then
    ensure_qdir
    cp -a "$file" "$QDIR/$(echo "$file" | tr '/' '_').bak" 2>/dev/null
    local tmpf
    tmpf="$(mktemp)"
    grep -Eiv "$IOC_LINE_REGEX" "$file" > "$tmpf"
    cat "$tmpf" > "$file"
    rm -f "$tmpf"
    echo "$file" >> "$QDIR/cleaned_persist_files.txt"
  fi
}

clean_persistence_high_ioc() {
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
    ensure_qdir
    cp "$tmpcron" "$QDIR/current_user_crontab.bak" 2>/dev/null
    grep -Eiv "$IOC_LINE_REGEX" "$tmpcron" | crontab -
    echo "current_user_crontab" >> "$QDIR/cleaned_persist_files.txt"
  fi

  rm -f "$tmpcron"

  local found_units
  found_units="$(grep -RIlE "$IOC_LINE_REGEX" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null)"

  for f in $found_units; do
    ensure_qdir
    cp -a "$f" "$QDIR/$(echo "$f" | tr '/' '_').bak" 2>/dev/null
    local svc
    svc="$(basename "$f")"
    systemctl disable --now "$svc" >/dev/null 2>&1
    chattr -i "$f" >/dev/null 2>&1
    mv "$f" "$f.disabled_by_pure_probe_${TS}" >/dev/null 2>&1
    echo "$f" >> "$QDIR/cleaned_persist_files.txt"
  done

  has systemctl && systemctl daemon-reload >/dev/null 2>&1

  if [ -n "${QDIR:-}" ] && [ -s "$QDIR/cleaned_persist_files.txt" ]; then
    ok "已清理高置信挖矿自启动"
  else
    ok "无需清理高置信挖矿自启动"
  fi
}

clean_low_cron_comment() {
  local changed=0 tmp
  tmp="$(mktemp)"
  crontab -l 2>/dev/null > "$tmp"

  if grep -Eq '^# \(/tmp/tmp\.[^)]* installed on ' "$tmp"; then
    ensure_qdir
    cp "$tmp" "$QDIR/current_user_crontab_before_comment_clean.bak" 2>/dev/null
    grep -Ev '^# \(/tmp/tmp\.[^)]* installed on ' "$tmp" | crontab -
    changed=1
  fi

  rm -f "$tmp"

  for f in /var/spool/cron/crontabs/* /var/spool/cron/*; do
    [ -f "$f" ] || continue

    if grep -Eq '^# \(/tmp/tmp\.[^)]* installed on ' "$f"; then
      ensure_qdir
      cp -a "$f" "$QDIR/$(echo "$f" | tr '/' '_').low_comment.bak" 2>/dev/null
      sed -i -E '/^# \(\/tmp\/tmp\.[^)]* installed on /d' "$f"
      changed=1
    fi
  done

  [ "$changed" = "1" ] && ok "已清理 crontab 临时文件注释误报" || ok "没有 crontab 临时文件注释需要清理"
}

clean_ioc() {
  title "高置信 IOC 自动清理"

  if [ "$DO_IOC" != "1" ]; then
    warn "跳过 IOC 清理"
    return 0
  fi

  kill_ioc_processes
  clean_ioc_files
  clean_persistence_high_ioc
  clean_low_cron_comment
}

print_summary() {
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
    local dce nat query auto force
    dce="$(yaml_get "$CONFIG" disable_command_execute)"
    nat="$(yaml_get "$CONFIG" disable_nat)"
    query="$(yaml_get "$CONFIG" disable_send_query)"
    auto="$(yaml_get "$CONFIG" disable_auto_update)"
    force="$(yaml_get "$CONFIG" disable_force_update)"

    out ""
    out "基础监控上报：保留"
    out "Agent 自动更新：$([ "$auto" = "false" ] && echo "开启" || echo "关闭")"
    out "HTTP/TCP/ICMP 主动探测权限：$([ "$query" = "false" ] && echo "开启" || echo "关闭")"
    out "远程命令/终端/文件/远程配置：$([ "$dce" = "true" ] && echo "关闭" || echo "开启")"
    out "NAT 内网穿透：$([ "$nat" = "true" ] && echo "关闭" || echo "开启")"
    out "面板强制更新：$([ "$force" = "true" ] && echo "关闭" || echo "开启")"
  fi

  if [ "$SANDBOX_OK" = "1" ]; then
    out "systemd 隔离：开启"
  else
    out "systemd 隔离：未开启"
  fi

  out ""

  if [ "$FOUND_HIGH_IOC" = "1" ]; then
    bad "IOC 结论：发现高置信 IOC，已尝试自动清理"
  elif [ "$FOUND_REVIEW" = "1" ]; then
    warn "IOC 结论：未发现高置信 IOC，但有中风险项需要人工确认"
  elif [ "$FOUND_LOW" = "1" ]; then
    ok "IOC 结论：只发现低风险 crontab 注释误报，已清理"
  else
    ok "IOC 结论：未发现高置信挖矿/对外攻击 IOC"
  fi

  if [ "$UPDATE_OK" = "1" ]; then
    ok "升级：已执行一次 Agent 原地升级"
  elif [ "$UPDATE_FAIL" = "1" ]; then
    bad "升级：失败，请手动执行 systemctl status 查看"
  else
    info "升级：本次未执行；后续靠 Agent 自动更新"
  fi

  if [ -n "${QDIR:-}" ] && [ -d "$QDIR" ]; then
    out ""
    out "隔离备份：$QDIR"
  fi
}

main() {
  need_root

  out "${B}Nezha Agent 探针加固 ${C0}"
  title "识别 Agent"
  detect_agent

  [ -n "$SERVICE" ] && ok "服务：$SERVICE" || warn "未识别到 systemd 服务"
  [ -n "$AGENT_BIN" ] && ok "二进制：$AGENT_BIN" || bad "未识别到 Agent 二进制"
  [ -n "$CONFIG" ] && ok "配置：$CONFIG" || warn "未识别到配置文件"

  if [ -n "$AGENT_BIN" ] && [ -x "$AGENT_BIN" ]; then
    cur="$(agent_version "$AGENT_BIN" | head -n1)"
    [ -n "$cur" ] && info "当前版本：$cur"
  fi

  ask_options

  apply_config
  apply_systemd_sandbox
  restart_agent

  update_agent_once

  detect_agent
  apply_config
  apply_systemd_sandbox
  restart_agent

  if [ "$DO_IOC" = "1" ]; then
    scan_ioc
    clean_ioc
    scan_ioc
  else
    warn "未执行 IOC 扫描"
  fi

  print_summary
}

main "$@"
