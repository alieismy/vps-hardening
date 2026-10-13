#!/usr/bin/env bash
# Static checks that need no VM (VT-73): shell syntax, Python syntax, LF line
# endings and generic secret patterns. CI runs ShellCheck separately from a
# pinned container image (.github/workflows/static.yml).

set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail() {
  printf '[x] %s\n' "$*" >&2
  exit 1
}

mapfile -t shell_files < <(git ls-files 'bin/*' 'lib/*.sh' 'tests/*.sh')
[ "${#shell_files[@]}" -gt 0 ] || fail 'no shell files found'
for file in "${shell_files[@]}"; do
  bash -n "$file" || fail "bash -n: $file"
done
printf '[+] bash -n: %d files\n' "${#shell_files[@]}"

mapfile -t python_files < <(git ls-files '*.py')
python3 -B -c 'import ast, sys; [ast.parse(open(p, encoding="utf-8").read(), p) for p in sys.argv[1:]]' \
  "${python_files[@]}"
printf '[+] Python syntax\n'

if git grep -lI $'\r' -- .; then
  fail 'files above contain CR characters; the repository uses LF only'
fi
printf '[+] LF line endings\n'

# Private keys and common token formats. Private identifiers (addresses,
# provider names, local paths) are checked outside the repository.
if git grep -nIE \
  -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' \
  -e 'gh[pousr]_[A-Za-z0-9]{36}' \
  -e 'github_pat_[A-Za-z0-9_]{22,}' \
  -e 'AKIA[0-9A-Z]{16}' \
  -e 'xox[abprs]-[A-Za-z0-9-]{10,}' \
  -e 'sk-[A-Za-z0-9_-]{32,}' -- .; then
  fail 'lines above look like secrets'
fi
printf '[+] no secret patterns\n'
