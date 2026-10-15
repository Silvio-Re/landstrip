#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) Jarkko Sakkinen 2026

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(git -C "$script_dir" rev-parse --show-toplevel)"
git_path="$(command -v git)"
mv_path="$(command -v mv)"
node_path="$(command -v node)"
version="$("$node_path" -p 'require(process.argv[1]).version' \
  "$repo_root/packages/landstrip-api/package.json")"
work="$(mktemp -d)"
cleanup() {
  local status=$?
  rm -rf -- "$work"
  return "$status"
}
trap cleanup EXIT

test_repo="$work/repo"
mocks="$work/mocks"
mkdir -p "$mocks" "$work/home"
"$git_path" clone --quiet --no-local "$repo_root" "$test_repo"
cp "$script_dir/package.sh" "$test_repo/packages/landstrip/scripts/package.sh"

(
  cd "$test_repo"
  "$git_path" config user.name 'Package Test'
  "$git_path" config user.email package-test@example.invalid
  "$git_path" add packages/landstrip/scripts/package.sh
  "$git_path" -c commit.gpgsign=false commit --quiet --allow-empty \
    -m 'test package transaction'

  mkdir -p npm/darwin-arm64/bin artifacts
  printf 'old binary\n' >npm/darwin-arm64/bin/landstrip
  for extension in tar.gz AppImage; do
    for suffix in '' .sha256 .commit; do
      printf 'old artifact %s%s\n' "$extension" "$suffix" \
        >"artifacts/landstrip-$version-darwin-arm64.$extension$suffix"
    done
  done
)
head_commit="$("$git_path" -C "$test_repo" rev-parse HEAD)"

cat >"$mocks/node" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == -e && "\${2:-}" == *process.platform* ]]; then
  printf 'test-host\n'
  exit 0
fi
exec "$node_path" "\$@"
EOF
cat >"$mocks/mv" <<EOF
#!/usr/bin/env bash
destination="\${!#}"
source="\${@: -2:1}"
if [[ "\${FAIL_PUBLISH:-0}" == 1 && "\$destination" == artifacts/*.sha256 && \
  ! -e "\${MV_FAIL_MARKER:-}" ]]; then
  : >"\$MV_FAIL_MARKER"
  exit 1
fi
if [[ "\${INTERRUPT_PUBLISH:-0}" == 1 && "\$destination" == artifacts/*.sha256 && \
  ! -e "\${MV_INTERRUPT_MARKER:-}" ]]; then
  : >"\$MV_INTERRUPT_MARKER"
  kill -TERM "\$PPID"
  sleep 1
  exit 143
fi
if [[ "\${FAIL_ROLLBACK:-0}" == 1 && "\$source" == */backup/* ]]; then
  exit 1
fi
exec "$mv_path" "\$@"
EOF
cat >"$mocks/rustc" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == --print && "${2:-}" == host-tuple ]]; then
  printf 'x86_64-unknown-linux-gnu\n'
  exit 0
fi
exit 1
EOF
cat >"$mocks/rustup" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
awk 'BEGIN {
  print "aarch64-apple-darwin"
  for (i = 0; i < 100000; i++) print "unused-target-" i
  print "x86_64-pc-windows-gnu"
}'
EOF
cat >"$mocks/zig" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$mocks/cargo-zigbuild" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
triple=
while (($#)); do
  if [[ "$1" == --target ]]; then
    triple="$2"
    break
  fi
  shift
done
[[ -n "$triple" ]]
if [[ "$triple" == x86_64-pc-windows-gnu ]]; then
  [[ "${FAIL_WINDOWS:-0}" != 1 ]] || exit 1
  binary=landstrip.exe
else
  binary=landstrip
fi
mkdir -p "$CARGO_TARGET_DIR/$triple/release"
printf 'new binary\n' >"$CARGO_TARGET_DIR/$triple/release/$binary"
EOF
chmod 755 "$mocks"/*

run_package() {
  (
    cd "$test_repo"
    env \
      PATH="$mocks:$PATH" \
      HOME="$work/home" \
      XDG_CACHE_HOME="${XDG_CACHE_HOME:-$work/home/.cache}" \
      NODE="$mocks/node" \
      RUSTC="$mocks/rustc" \
      CARGO_ZIGBUILD="$mocks/cargo-zigbuild" \
      ZIG="$mocks/zig" \
      PACKAGE_STRICT=1 \
      FAIL_WINDOWS="${FAIL_WINDOWS:-0}" \
      FAIL_PUBLISH="${FAIL_PUBLISH:-0}" \
      FAIL_ROLLBACK="${FAIL_ROLLBACK:-0}" \
      INTERRUPT_PUBLISH="${INTERRUPT_PUBLISH:-0}" \
      MV_FAIL_MARKER="$work/mv-failed" \
      MV_INTERRUPT_MARKER="$work/mv-interrupted" \
      ./packages/landstrip/scripts/package.sh "$@"
  )
}

assert_old_outputs() {
  [[ "$(<"$test_repo/npm/darwin-arm64/bin/landstrip")" == 'old binary' ]]
  for extension in tar.gz AppImage; do
    for suffix in '' .sha256 .commit; do
      [[ "$(<"$test_repo/artifacts/landstrip-$version-darwin-arm64.$extension$suffix")" \
        == "old artifact $extension$suffix" ]]
    done
  done
}

assert_no_stage() {
  if compgen -G "$test_repo/.package-stage.*" >/dev/null; then
    printf 'package staging directory was not removed\n' >&2
    exit 1
  fi
}

sha256_digest() {
  local output
  if command -v sha256sum >/dev/null 2>&1; then
    output="$(sha256sum "$1")"
  else
    output="$(shasum -a 256 "$1")"
  fi
  printf '%s\n' "${output%% *}"
}

printf 'not a directory\n' >"$work/cache-blocker"
status=0
XDG_CACHE_HOME="$work/cache-blocker" run_package darwin-arm64 win32-x64 \
  >"$work/cargo-home-failure.log" 2>&1 || status=$?
[[ "$status" == 1 ]] || {
  printf 'expected Cargo home setup failure to exit 1; got %s\n' "$status" >&2
  cat "$work/cargo-home-failure.log" >&2
  exit 1
}
assert_old_outputs
assert_no_stage
status=0
FAIL_WINDOWS=1 run_package darwin-arm64 win32-x64 \
  >"$work/build-failure.log" 2>&1 || status=$?
[[ "$status" == 1 ]] || {
  printf 'expected strict packaging to exit 1; got %s\n' "$status" >&2
  cat "$work/build-failure.log" >&2
  exit 1
}
grep -Fq 'PACKAGE_STRICT=1 and some platforms failed' "$work/build-failure.log" || {
  cat "$work/build-failure.log" >&2
  exit 1
}
assert_old_outputs
assert_no_stage

status=0
FAIL_PUBLISH=1 run_package darwin-arm64 win32-x64 \
  >"$work/publish-failure.log" 2>&1 || status=$?
[[ "$status" == 1 ]] || {
  printf 'expected failed publication to exit 1; got %s\n' "$status" >&2
  cat "$work/publish-failure.log" >&2
  exit 1
}
if ! grep -Fq 'cannot publish artifact:' "$work/publish-failure.log" || \
  ! grep -Fq 'previous release outputs restored' "$work/publish-failure.log"; then
  cat "$work/publish-failure.log" >&2
  exit 1
fi
assert_old_outputs
assert_no_stage

status=0
INTERRUPT_PUBLISH=1 run_package darwin-arm64 win32-x64 \
  >"$work/publish-interrupt.log" 2>&1 || status=$?
[[ "$status" == 143 ]] || {
  printf 'expected interrupted publication to exit 143; got %s\n' "$status" >&2
  cat "$work/publish-interrupt.log" >&2
  exit 1
}
grep -Fq 'previous release outputs restored' "$work/publish-interrupt.log"
assert_old_outputs
assert_no_stage

if ! run_package darwin-arm64 win32-x64 >"$work/package-success.log" 2>&1; then
  cat "$work/package-success.log" >&2
  exit 1
fi
[[ "$(<"$test_repo/npm/darwin-arm64/bin/landstrip")" == 'new binary' ]]
[[ "$(<"$test_repo/npm/win32-x64/bin/landstrip.exe")" == 'new binary' ]]
for platform in darwin-arm64 win32-x64; do
  binary=landstrip
  [[ "$platform" == win32-x64 ]] && binary=landstrip.exe
  artifact="$test_repo/artifacts/landstrip-$version-$platform.tar.gz"
  digest="$(sha256_digest "$artifact")"
  [[ "$(tar -xOzf "$artifact" "$binary")" == 'new binary' ]]
  [[ "$(<"$artifact.sha256")" == "$digest  $(basename "$artifact")" ]]
  [[ "$(<"$artifact.commit")" == "$head_commit" ]]
  for suffix in '' .sha256 .commit; do
    [[ ! -e "$test_repo/artifacts/landstrip-$version-$platform.AppImage$suffix" ]]
  done
done
assert_no_stage

status=0
run_package darwin-arm64 darwin-arm64 >"$work/duplicate.log" 2>&1 || status=$?
[[ "$status" == 1 ]]
grep -Fq 'duplicate platform: darwin-arm64' "$work/duplicate.log"

rm -f "$work/mv-failed"
status=0
FAIL_PUBLISH=1 FAIL_ROLLBACK=1 run_package darwin-arm64 win32-x64 \
  >"$work/rollback-failure.log" 2>&1 || status=$?
[[ "$status" == 1 ]]
grep -Fq 'release publication and rollback failed; backups preserved at' \
  "$work/rollback-failure.log"
shopt -s nullglob
stages=("$test_repo"/.package-stage.*)
shopt -u nullglob
((${#stages[@]} == 1))
[[ -f "${stages[0]}/backup/npm/darwin-arm64/bin/landstrip" ]]
