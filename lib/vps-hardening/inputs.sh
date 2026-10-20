# shellcheck shell=bash
# Command-line inputs for preflight/apply (requirements section 6).
# Syntax and value errors exit with VH_EXIT_USAGE before any host check runs.
# Globals defined here are read by the other modules, which ShellCheck checks separately.
# shellcheck disable=SC2034

VH_IN_PANEL_PORT="$VH_PANEL_PORT_DEFAULT"
VH_IN_OPEN=()
VH_IN_TIMEOUT="$VH_TIMEOUT_DEFAULT"

readonly VH_MAX_OPEN=16

is_port() {
  [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$1" -le 65535 ]
}

option_value() {
  # $1 option name, $2 remaining argument count, $3 candidate value
  [ "$2" -ge 2 ] || usage_error "$1 缺少取值"
  case "$3" in
    --*) usage_error "$1 缺少取值" ;;
  esac
}

parse_host_options() {
  local arg
  while [ "$#" -gt 0 ]; do
    arg="$1"
    case "$arg" in
      --*=*)
        shift
        set -- "${arg%%=*}" "${arg#*=}" "$@"
        continue
        ;;
    esac
    case "$arg" in
      --panel-port)
        option_value "$arg" "$#" "${2-}"
        VH_IN_PANEL_PORT="$2"
        ;;
      --open)
        option_value "$arg" "$#" "${2-}"
        VH_IN_OPEN+=("$2")
        ;;
      --confirm-timeout)
        option_value "$arg" "$#" "${2-}"
        VH_IN_TIMEOUT="$2"
        ;;
      *)
        usage_error "未知参数：$arg"
        ;;
    esac
    shift 2
  done
  validate_host_options
}

validate_host_options() {
  local spec port proto family seen=' ' normalized=()

  is_port "$VH_IN_PANEL_PORT" || usage_error "面板端口不合法：$VH_IN_PANEL_PORT（1–65535）"
  [ "$VH_IN_PANEL_PORT" -ne 22 ] || usage_error '面板端口不能是 22'

  [ "${#VH_IN_OPEN[@]}" -le "$VH_MAX_OPEN" ] || usage_error "公开端口最多 $VH_MAX_OPEN 个"
  for spec in "${VH_IN_OPEN[@]}"; do
    [[ "$spec" =~ ^([1-9][0-9]{0,4})/(tcp|udp)(/(both|ipv4|ipv6))?$ ]] ||
      usage_error "公开端口格式不合法：$spec（应为 端口/tcp|udp[/both|ipv4|ipv6]，例如 443/tcp）"
    port="${BASH_REMATCH[1]}"
    proto="${BASH_REMATCH[2]}"
    family="${BASH_REMATCH[4]:-both}"
    is_port "$port" || usage_error "公开端口超出范围：$spec"
    [ "$port" -ne 22 ] || usage_error '公开端口不能是 22：SSH 端口总是放行'
    [ "$port" -ne "$VH_IN_PANEL_PORT" ] || usage_error "公开端口 $port 与面板端口相同；面板只经 SSH 隧道访问，不能开放"
    case "$seen" in
      *" $port/$proto "*) usage_error "公开端口重复：$port/$proto" ;;
    esac
    seen="$seen$port/$proto "
    normalized+=("$port/$proto/$family")
  done
  VH_IN_OPEN=("${normalized[@]}")

  if ! [[ "$VH_IN_TIMEOUT" =~ ^[1-9][0-9]?$ ]] || [ "$VH_IN_TIMEOUT" -lt "$VH_TIMEOUT_MIN" ] ||
    [ "$VH_IN_TIMEOUT" -gt "$VH_TIMEOUT_MAX" ]; then
    usage_error "--confirm-timeout 应为 $VH_TIMEOUT_MIN～$VH_TIMEOUT_MAX 之间的整数分钟：$VH_IN_TIMEOUT"
  fi
}
