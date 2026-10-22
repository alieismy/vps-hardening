# shellcheck shell=bash
# Command-line inputs for preflight, apply and ports (requirements section 6).
# Syntax and value errors exit with VH_EXIT_USAGE before any host check runs.
# Globals defined here are read by the other modules, which ShellCheck checks separately.
# shellcheck disable=SC2034

VH_IN_PANEL_PORT="$VH_PANEL_PORT_DEFAULT"
VH_IN_OPEN=()
VH_IN_TIMEOUT="$VH_TIMEOUT_DEFAULT"
# ports: specifications to add and to remove, as given.
VH_IN_ADD=()
VH_IN_REMOVE=()
# split_port_spec results.
VH_SPEC_PORT=''
VH_SPEC_PROTO=''
VH_SPEC_FAMILY=''

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

# split_port_spec SPEC: PORT/PROTO[/FAMILY] into VH_SPEC_PORT, VH_SPEC_PROTO
# and VH_SPEC_FAMILY (both when omitted). Exits with a usage error when the
# format or range is wrong.
split_port_spec() {
  [[ "$1" =~ ^([1-9][0-9]{0,4})/(tcp|udp)(/(both|ipv4|ipv6))?$ ]] ||
    usage_error "公开端口格式不合法：$1（应为 端口/tcp|udp[/both|ipv4|ipv6]，例如 443/tcp）"
  VH_SPEC_PORT="${BASH_REMATCH[1]}"
  VH_SPEC_PROTO="${BASH_REMATCH[2]}"
  VH_SPEC_FAMILY="${BASH_REMATCH[4]:-both}"
  is_port "$VH_SPEC_PORT" || usage_error "公开端口超出范围：$1"
}

# check_public_port PANEL: the port in VH_SPEC_PORT may be opened (FR-14, D14, D16).
check_public_port() {
  [ "$VH_SPEC_PORT" -ne 22 ] || usage_error '公开端口不能是 22：SSH 端口总是放行'
  [ "$VH_SPEC_PORT" -ne "$1" ] || usage_error "公开端口 $VH_SPEC_PORT 与面板端口相同；面板只经 SSH 隧道访问，不能开放"
  [ "$VH_SPEC_PORT/$VH_SPEC_PROTO" != 80/tcp ] || usage_error '公开端口不能是 80/tcp：证书用 DNS-01 签发，80/tcp 不开放（D14）'
}

validate_timeout() {
  if ! [[ "$VH_IN_TIMEOUT" =~ ^[1-9][0-9]?$ ]] || [ "$VH_IN_TIMEOUT" -lt "$VH_TIMEOUT_MIN" ] ||
    [ "$VH_IN_TIMEOUT" -gt "$VH_TIMEOUT_MAX" ]; then
    usage_error "--confirm-timeout 应为 $VH_TIMEOUT_MIN～$VH_TIMEOUT_MAX 之间的整数分钟：$VH_IN_TIMEOUT"
  fi
}

validate_host_options() {
  local spec seen=' ' normalized=()

  is_port "$VH_IN_PANEL_PORT" || usage_error "面板端口不合法：$VH_IN_PANEL_PORT（1–65535）"
  [ "$VH_IN_PANEL_PORT" -ne 22 ] || usage_error '面板端口不能是 22'

  [ "${#VH_IN_OPEN[@]}" -le "$VH_MAX_OPEN" ] || usage_error "公开端口最多 $VH_MAX_OPEN 个"
  for spec in "${VH_IN_OPEN[@]}"; do
    split_port_spec "$spec"
    check_public_port "$VH_IN_PANEL_PORT"
    case "$seen" in
      *" $VH_SPEC_PORT/$VH_SPEC_PROTO "*) usage_error "公开端口重复：$VH_SPEC_PORT/$VH_SPEC_PROTO" ;;
    esac
    seen="$seen$VH_SPEC_PORT/$VH_SPEC_PROTO "
    normalized+=("$VH_SPEC_PORT/$VH_SPEC_PROTO/$VH_SPEC_FAMILY")
  done
  VH_IN_OPEN=("${normalized[@]}")
  validate_timeout
}

# ports: --add and --remove (repeatable) and --confirm-timeout. Checks that
# need the apply record (the panel port, the declared ports) are in ports.sh.
parse_ports_options() {
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
      --add)
        option_value "$arg" "$#" "${2-}"
        VH_IN_ADD+=("$2")
        ;;
      --remove)
        option_value "$arg" "$#" "${2-}"
        VH_IN_REMOVE+=("$2")
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
  [ "$((${#VH_IN_ADD[@]} + ${#VH_IN_REMOVE[@]}))" -gt 0 ] || usage_error 'ports 需要至少一个 --add 或 --remove'
  check_spec_list --add "${VH_IN_ADD[@]}"
  check_spec_list --remove "${VH_IN_REMOVE[@]}"
  validate_timeout
}

# check_spec_list OPTION SPEC...: format and range, and no PORT/PROTO twice.
check_spec_list() {
  local option="$1" spec seen=' '
  shift
  for spec in "$@"; do
    split_port_spec "$spec"
    case "$seen" in
      *" $VH_SPEC_PORT/$VH_SPEC_PROTO "*) usage_error "$option 重复：$VH_SPEC_PORT/$VH_SPEC_PROTO" ;;
    esac
    seen="$seen$VH_SPEC_PORT/$VH_SPEC_PROTO "
  done
}
