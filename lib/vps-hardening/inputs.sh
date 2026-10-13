# shellcheck shell=bash
# Command-line inputs for preflight/apply (requirements section 6).
# Syntax and value errors exit with VH_EXIT_USAGE before any host check runs.
# Globals defined here are read by the other modules, which ShellCheck checks separately.
# shellcheck disable=SC2034

VH_IN_USER=''
VH_IN_PUBKEY_FILES=()
VH_IN_PANEL_PORT="$VH_PANEL_PORT_DEFAULT"
VH_IN_OPEN=()
VH_IN_MAXRETRY="$VH_MAXRETRY_DEFAULT"
VH_IN_TIMEOUT="$VH_TIMEOUT_DEFAULT"
# Validated key lines ("type base64 [comment]") and their SHA256 fingerprints.
VH_KEY_LINES=()
VH_KEY_TYPES=()
VH_KEY_FPRS=()

readonly VH_MAX_KEYS=20
readonly VH_MAX_OPEN=16
readonly VH_MAX_KEYFILE_BYTES=65536

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
      --user)
        option_value "$arg" "$#" "${2-}"
        VH_IN_USER="$2"
        ;;
      --pubkey-file)
        option_value "$arg" "$#" "${2-}"
        VH_IN_PUBKEY_FILES+=("$2")
        ;;
      --panel-port)
        option_value "$arg" "$#" "${2-}"
        VH_IN_PANEL_PORT="$2"
        ;;
      --open)
        option_value "$arg" "$#" "${2-}"
        VH_IN_OPEN+=("$2")
        ;;
      --maxretry)
        option_value "$arg" "$#" "${2-}"
        VH_IN_MAXRETRY="$2"
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

  [ -n "$VH_IN_USER" ] || usage_error '缺少 --user（要创建的管理用户名）'
  [[ "$VH_IN_USER" =~ ^[a-z][a-z0-9_-]{0,31}$ ]] ||
    usage_error "用户名不合法：$VH_IN_USER（以小写字母开头，只含小写字母、数字、_ 和 -，最长 32 个字符）"
  [ "$VH_IN_USER" != root ] || usage_error '管理用户不能是 root'

  [ "${#VH_IN_PUBKEY_FILES[@]}" -gt 0 ] || usage_error '缺少 --pubkey-file（管理员的公钥文件）'

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

  case "$VH_IN_MAXRETRY" in
    3 | 6) ;;
    *) usage_error "--maxretry 只能是 3 或 6：$VH_IN_MAXRETRY" ;;
  esac

  if ! [[ "$VH_IN_TIMEOUT" =~ ^[1-9][0-9]?$ ]] || [ "$VH_IN_TIMEOUT" -lt "$VH_TIMEOUT_MIN" ] ||
    [ "$VH_IN_TIMEOUT" -gt "$VH_TIMEOUT_MAX" ]; then
    usage_error "--confirm-timeout 应为 $VH_TIMEOUT_MIN～$VH_TIMEOUT_MAX 之间的整数分钟：$VH_IN_TIMEOUT"
  fi

  load_pubkeys
}

# Accept only plain public key lines. Options such as command= or
# no-port-forwarding would be copied to the admin user and could break the
# panel tunnel (FR-07), so such lines are rejected rather than stripped.
load_pubkeys() {
  local file line lineno size keyfile fpr type seen_fprs=' '
  vh_tmp_init
  keyfile="$VH_TMP/pubkey"
  for file in "${VH_IN_PUBKEY_FILES[@]}"; do
    if ! [ -f "$file" ] || ! [ -r "$file" ]; then
      usage_error "公钥文件不存在或不可读：$file"
    fi
    size="$(stat -c %s -- "$file")"
    [ "$size" -le "$VH_MAX_KEYFILE_BYTES" ] || usage_error "公钥文件过大：$file"
    if grep -q -- 'PRIVATE KEY' "$file"; then
      usage_error "$file 是私钥。只接受公钥（通常是 .pub 文件），私钥不要上传到服务器"
    fi
    lineno=0
    while IFS= read -r line || [ -n "$line" ]; do
      lineno=$((lineno + 1))
      line="${line%$'\r'}"
      line="${line#"${line%%[![:space:]]*}"}"
      case "$line" in
        '' | '#'*) continue ;;
      esac
      if ! [[ "$line" =~ ^(ssh-[a-z0-9-]+|ecdsa-sha2-[a-z0-9-]+|sk-[a-z0-9@.-]+)[[:space:]]+[A-Za-z0-9+/]+=*([[:space:]].*)?$ ]]; then
        usage_error "$file 第 $lineno 行不是单纯的公钥。不支持带选项（如 command=、from=）的行，请只提供 \"类型 密钥 注释\" 格式"
      fi
      type="${BASH_REMATCH[1]}"
      printf '%s\n' "$line" >"$keyfile"
      fpr="$(ssh-keygen -l -E sha256 -f "$keyfile" 2>/dev/null | awk '{print $2}')" || fpr=''
      [ -n "$fpr" ] || usage_error "$file 第 $lineno 行无法解析为公钥"
      case "$seen_fprs" in
        *" $fpr "*) continue ;;
      esac
      seen_fprs="$seen_fprs$fpr "
      VH_KEY_LINES+=("$line")
      VH_KEY_TYPES+=("$type")
      VH_KEY_FPRS+=("$fpr")
    done <"$file"
  done
  rm -f -- "$keyfile"
  [ "${#VH_KEY_LINES[@]}" -gt 0 ] || usage_error '公钥文件中没有可用的公钥'
  [ "${#VH_KEY_LINES[@]}" -le "$VH_MAX_KEYS" ] || usage_error "公钥最多 $VH_MAX_KEYS 把"
}
