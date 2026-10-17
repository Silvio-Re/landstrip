#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (C) Jarkko Sakkinen 2026
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT

write_elf() {
  local path="$1" architecture="$2" appimage_magic="$3" kind="${4:-exec}" machine code

  case "$architecture" in
    x64)
      machine='\076\000'
      code='\061\377\270\074\000\000\000\017\005\220\220\220\220\220\220\220'
      ;;
    arm64)
      machine='\267\000'
      code='\000\000\200\322\250\013\200\322\001\000\000\324\037\040\003\325'
      ;;
  esac

  {
    printf '\177ELF\002\001\001\000%b\000\000\000\000\000' "$appimage_magic"
    if [[ "$kind" == pie ]]; then
      printf '\003\000%b\001\000\000\000' "$machine"
      printf '\260\000\100\000\000\000\000\000'
      printf '\100\000\000\000\000\000\000\000'
      printf '\000\000\000\000\000\000\000\000'
      printf '\000\000\000\000\100\000\070\000\002\000\000\000\000\000\000\000'
      printf '\001\000\000\000\005\000\000\000'
      printf '\000\000\000\000\000\000\000\000'
      printf '\000\000\100\000\000\000\000\000'
      printf '\000\000\100\000\000\000\000\000'
      printf '\340\000\000\000\000\000\000\000'
      printf '\340\000\000\000\000\000\000\000'
      printf '\000\020\000\000\000\000\000\000'
      printf '\002\000\000\000\006\000\000\000'
      printf '\300\000\000\000\000\000\000\000'
      printf '\300\000\100\000\000\000\000\000'
      printf '\300\000\100\000\000\000\000\000'
      printf '\040\000\000\000\000\000\000\000'
      printf '\040\000\000\000\000\000\000\000'
      printf '\010\000\000\000\000\000\000\000'
      printf '%b' "$code"
      printf '\373\377\377\157\000\000\000\000\000\000\000\010\000\000\000\000'
      printf '\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000'
    else
      printf '\002\000%b\001\000\000\000' "$machine"
      printf '\170\000\100\000\000\000\000\000'
      printf '\100\000\000\000\000\000\000\000'
      printf '\000\000\000\000\000\000\000\000'
      printf '\000\000\000\000\100\000\070\000\001\000\000\000\000\000\000\000'
      printf '\001\000\000\000\005\000\000\000'
      printf '\000\000\000\000\000\000\000\000'
      printf '\000\000\100\000\000\000\000\000'
      printf '\000\000\100\000\000\000\000\000'
      printf '\210\000\000\000\000\000\000\000'
      printf '\210\000\000\000\000\000\000\000'
      printf '\000\020\000\000\000\000\000\000'
      printf '%b' "$code"
    fi
  } >"$path"
  chmod 755 "$path"
}

x64_binary="$temporary/landstrip-x64"
x64_binary_link="$temporary/landstrip-x64-link"
arm64_binary="$temporary/landstrip-arm64"
x64_runtime="$temporary/runtime-x64"
arm64_runtime="$temporary/runtime-arm64"
stub="$temporary/mksquashfs"
write_elf "$x64_binary" x64 '\000\000\000'
ln -s "$x64_binary" "$x64_binary_link"
write_elf "$arm64_binary" arm64 '\000\000\000'
write_elf "$x64_runtime" x64 'AI\002' pie
write_elf "$arm64_runtime" arm64 'AI\002' pie

cat >"$stub" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

appdir="$1"
output="$2"
[[ "$3" == -comp && "$4" == gzip && "$5" == -noappend && "$6" == -all-root ]]
[[ "$(readlink "$appdir/AppRun")" == usr/bin/landstrip ]]
cmp "$TEST_BINARY" "$appdir/usr/bin/landstrip"
grep -Fxq 'Terminal=true' "$appdir/landstrip.desktop"
[[ -L "$appdir/.DirIcon" ]]
[[ -f "$appdir/usr/share/licenses/landstrip/LICENSE" ]]
[[ -f "$appdir/usr/share/licenses/landstrip/AppImage-runtime.LICENSE" ]]
# A minimal superblock exercises format checks without running the target ELF.
printf 'hsqs' >"$output"
dd if=/dev/zero bs=1 count=92 >>"$output" 2>/dev/null
printf '\001\000' | dd of="$output" bs=1 seek=20 conv=notrunc 2>/dev/null
printf '\004\000\000\000' | dd of="$output" bs=1 seek=28 conv=notrunc 2>/dev/null
printf '\140' | dd of="$output" bs=1 seek=40 conv=notrunc 2>/dev/null
EOF
chmod 755 "$stub"

for platform in linux-x64 linux-arm64; do
  output="$temporary/$platform/landstrip"
  case "$platform" in
    linux-x64) binary="$x64_binary_link" ;;
    linux-arm64) binary="$arm64_binary" ;;
  esac
  TEST_BINARY="$binary" \
    MKSQUASHFS="$stub" APPIMAGE_RUNTIME_X86_64="$x64_runtime" \
    APPIMAGE_RUNTIME_AARCH64="$arm64_runtime" \
    "$script_dir/make-appimage.sh" "$platform" "$binary" "$output"
  [[ -x "$output" ]]
done

wrong_input="$temporary/wrong-input"
if TEST_BINARY="$arm64_binary" \
  MKSQUASHFS="$stub" APPIMAGE_RUNTIME_X86_64="$x64_runtime" \
  "$script_dir/make-appimage.sh" linux-x64 "$arm64_binary" "$wrong_input" 2>/dev/null; then
  printf 'wrong input architecture unexpectedly succeeded\n' >&2
  exit 1
fi
[[ ! -e "$wrong_input" ]]

non_elf="$temporary/non-elf"
non_elf_output="$temporary/non-elf-output"
printf 'MZ' >"$non_elf"
chmod 755 "$non_elf"
if TEST_BINARY="$non_elf" \
  MKSQUASHFS="$stub" APPIMAGE_RUNTIME_X86_64="$x64_runtime" \
  "$script_dir/make-appimage.sh" linux-x64 "$non_elf" "$non_elf_output" 2>/dev/null; then
  printf 'non-ELF input unexpectedly succeeded\n' >&2
  exit 1
fi
[[ ! -e "$non_elf_output" ]]

truncated_elf="$temporary/truncated-elf"
truncated_output="$temporary/truncated-output"
head -c 24 "$x64_binary" >"$truncated_elf"
chmod 755 "$truncated_elf"
if TEST_BINARY="$truncated_elf" \
  MKSQUASHFS="$stub" APPIMAGE_RUNTIME_X86_64="$x64_runtime" \
  "$script_dir/make-appimage.sh" linux-x64 "$truncated_elf" "$truncated_output" 2>/dev/null; then
  printf 'truncated ELF unexpectedly succeeded\n' >&2
  exit 1
fi
[[ ! -e "$truncated_output" ]]

shared_library="$temporary/shared-library"
shared_output="$temporary/shared-output"
cp "$x64_binary" "$shared_library"
printf '\003\000' | dd of="$shared_library" bs=1 seek=16 conv=notrunc 2>/dev/null
if TEST_BINARY="$shared_library" \
  MKSQUASHFS="$stub" APPIMAGE_RUNTIME_X86_64="$x64_runtime" \
  "$script_dir/make-appimage.sh" linux-x64 "$shared_library" "$shared_output" 2>/dev/null; then
  printf 'shared library unexpectedly succeeded\n' >&2
  exit 1
fi
[[ ! -e "$shared_output" ]]

wrong_runtime="$temporary/wrong-runtime"
if TEST_BINARY="$arm64_binary" \
  MKSQUASHFS="$stub" APPIMAGE_RUNTIME_AARCH64="$x64_runtime" \
  "$script_dir/make-appimage.sh" linux-arm64 "$arm64_binary" "$wrong_runtime" 2>/dev/null; then
  printf 'wrong AppImage architecture unexpectedly succeeded\n' >&2
  exit 1
fi
[[ ! -e "$wrong_runtime" ]]

if MKSQUASHFS="$stub" \
  "$script_dir/make-appimage.sh" linux-riscv64 "$x64_binary" "$temporary/bad" 2>/dev/null; then
  printf 'unsupported platform unexpectedly succeeded\n' >&2
  exit 1
fi

if [[ "$(uname -s)" != Linux ]]; then
  container_stub="$temporary/container-stub"
  container_records="$temporary/container-records"
  mkdir -p "$container_records"
  cat >"$container_stub" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == run ]]
shift
[[ "$1" == --rm ]]
shift
[[ "$1" == --platform ]]
shift
platform="$1"
shift
printf '%s\n' "$platform" >"$TEST_CONTAINER_RECORDS/platform"
while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --cpus) shift; printf '%s\n' "$1" >"$TEST_CONTAINER_RECORDS/cpus"; shift ;;
    --memory) shift; printf '%s\n' "$1" >"$TEST_CONTAINER_RECORDS/memory"; shift ;;
    *) shift ;;
  esac
done
output_name=""
out_dir=""
while (($# > 0)); do
  case "$1" in
    -e)
      shift
      case "$1" in
        OUTPUT_NAME=*) output_name="${1#OUTPUT_NAME=}" ;;
      esac
      shift
      ;;
    -v)
      shift
      case "$1" in
        *:/out) out_dir="${1%:/out}" ;;
      esac
      shift
      ;;
    alpine:*)
      shift
      break
      ;;
    *)
      shift
      ;;
  esac
done
printf '%s\n' "$output_name" >"$TEST_CONTAINER_RECORDS/output_name"
[[ "$*" == *'mksquashfs /AppDir '*'-comp gzip -noappend -all-root'* ]]
offset="$(wc -c <"$TEST_RUNTIME")"
dd if="$TEST_APPIMAGE" of="$out_dir/$output_name" bs=1 skip="$offset" 2>/dev/null
EOF
  chmod 755 "$container_stub"

  container_output="$temporary/container-output/landstrip"
  TEST_BINARY="$arm64_binary" TEST_APPIMAGE="$temporary/linux-arm64/landstrip" \
    TEST_RUNTIME="$arm64_runtime" TEST_CONTAINER_RECORDS="$container_records" \
    CONTAINER="$container_stub" CONTAINER_CPUS=4 CONTAINER_MEMORY=2G \
    APPIMAGE_RUNTIME_AARCH64="$arm64_runtime" \
    "$script_dir/make-appimage.sh" linux-arm64 "$arm64_binary" "$container_output"
  [[ -x "$container_output" ]]
  case "$(uname -m)" in
    x86_64|amd64) expected_platform=linux/amd64 ;;
    aarch64|arm64) expected_platform=linux/arm64 ;;
  esac
  [[ "$(cat "$container_records/platform")" == "$expected_platform" ]]
  [[ "$(cat "$container_records/cpus")" == 4 ]]
  [[ "$(cat "$container_records/memory")" == 2G ]]

  if CONTAINER="$temporary/no-such-container" \
    APPIMAGE_RUNTIME_AARCH64="$arm64_runtime" \
    "$script_dir/make-appimage.sh" linux-arm64 "$arm64_binary" "$temporary/bad-container" 2>/dev/null; then
    printf 'non-existent container command unexpectedly succeeded\n' >&2
    exit 1
  fi
fi
