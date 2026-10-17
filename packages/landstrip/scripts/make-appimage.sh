#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (C) Jarkko Sakkinen 2026
#
# Build a type-2 AppImage around a packaged landstrip binary.
# Usage: make-appimage.sh <linux-x64|linux-arm64> <binary> <output>
set -euo pipefail

die() {
  printf '%s\n' "$1" >&2
  exit 1
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "required command not found: sha256sum or shasum"
  fi
}

download_verified() {
  local url="$1" expected="$2" destination="$3" temporary

  if [[ -f "$destination" ]] && [[ "$(sha256 "$destination")" == "$expected" ]]; then
    return
  fi

  command -v "${CURL:-curl}" >/dev/null 2>&1 || die "required command not found: ${CURL:-curl}"
  mkdir -p "$(dirname "$destination")"
  temporary="${destination}.tmp.$$"
  rm -f "$temporary"
  if ! "${CURL:-curl}" -fL --retry 3 -o "$temporary" "$url"; then
    rm -f "$temporary"
    die "failed to download $url"
  fi
  if [[ "$(sha256 "$temporary")" != "$expected" ]]; then
    rm -f "$temporary"
    die "checksum mismatch for $url"
  fi
  mv "$temporary" "$destination"
}

is_type2_appimage() {
  [[ "$(od -An -tx1 -j8 -N3 "$1" | tr -d ' \n')" == 414902 ]]
}

read_uint_le() {
  local path="$1" offset="$2" count="$3" destination="$4"
  local byte bytes shift=0 value=0
  local -a octets

  bytes="$(od -An -tu1 -j "$offset" -N "$count" "$path")" || return 1
  read -r -a octets <<<"$bytes"
  ((${#octets[@]} == count)) || return 1
  for byte in "${octets[@]}"; do
    ((shift < 56 || byte < 128)) || return 1
    value=$((value + (byte << shift)))
    shift=$((shift + 8))
  done
  printf -v "$destination" '%u' "$value"
}

verify_elf_architecture() {
  local path="$1" label="$2" ident file_size elf_type machine version entry
  local phoff ehsize phentsize phnum index base ptype flags poffset vaddr filesz memsz
  local dynamic_offset=0 dynamic_size=0 dynamic_tag dynamic_value dynamic_terminated=0
  local has_executable_load=0 has_pie_flag=0

  file_size="$(wc -c <"$path")" || file_size=0
  ident="$(od -An -tx1 -j0 -N7 "$path" | tr -d ' \n')" || ident=
  if ((file_size < 64)) || [[ "$ident" != 7f454c46020101 ]]; then
    printf '%s is not a complete 64-bit little-endian ELF: %s\n' "$label" "$path" >&2
    return 1
  fi

  if ! read_uint_le "$path" 16 2 elf_type ||
    ! read_uint_le "$path" 18 2 machine ||
    ! read_uint_le "$path" 20 4 version ||
    ! read_uint_le "$path" 24 8 entry ||
    ! read_uint_le "$path" 32 8 phoff ||
    ! read_uint_le "$path" 52 2 ehsize ||
    ! read_uint_le "$path" 54 2 phentsize ||
    ! read_uint_le "$path" 56 2 phnum; then
    printf '%s has a malformed ELF header: %s\n' "$label" "$path" >&2
    return 1
  fi
  if ((elf_type != 2 && elf_type != 3)) || ((version != 1)) ||
    ((entry == 0)) || ((ehsize != 64)) || ((phentsize != 56)) || ((phnum == 0)) ||
    ((phoff < 64 || phoff > file_size || phnum > (file_size - phoff) / phentsize)); then
    printf '%s is not a structurally valid executable ELF: %s\n' "$label" "$path" >&2
    return 1
  fi
  if ((machine != elf_machine)); then
    printf '%s has the wrong architecture for %s: ELF machine %s\n' \
      "$label" "$platform" "$machine" >&2
    return 1
  fi

  index=0
  while ((index < phnum)); do
    base=$((phoff + index * phentsize))
    if ! read_uint_le "$path" "$base" 4 ptype; then
      printf '%s has a malformed program header: %s\n' "$label" "$path" >&2
      return 1
    fi
    if ((ptype == 1 || ptype == 2)); then
      if ! read_uint_le "$path" $((base + 8)) 8 poffset ||
        ! read_uint_le "$path" $((base + 32)) 8 filesz; then
        printf '%s has a malformed segment: %s\n' "$label" "$path" >&2
        return 1
      fi
      if ((poffset > file_size || filesz > file_size - poffset)); then
        printf '%s has a segment outside the file: %s\n' "$label" "$path" >&2
        return 1
      fi
    fi
    if ((ptype == 1)); then
      if ! read_uint_le "$path" $((base + 4)) 4 flags ||
        ! read_uint_le "$path" $((base + 16)) 8 vaddr ||
        ! read_uint_le "$path" $((base + 40)) 8 memsz; then
        printf '%s has a malformed load segment: %s\n' "$label" "$path" >&2
        return 1
      fi
      if ((filesz > memsz)); then
        printf '%s has an invalid load segment: %s\n' "$label" "$path" >&2
        return 1
      fi
      if ((flags & 1)) && ((entry >= vaddr && entry - vaddr < memsz)); then
        has_executable_load=1
      fi
    elif ((ptype == 2)); then
      dynamic_offset=$poffset
      dynamic_size=$filesz
    fi
    index=$((index + 1))
  done

  if ((has_executable_load == 0)); then
    printf '%s does not map its entry point in an executable load segment: %s\n' \
      "$label" "$path" >&2
    return 1
  fi
  if ((elf_type == 3)); then
    if ((dynamic_size == 0 || dynamic_size % 16 != 0)); then
      printf '%s is ET_DYN without a valid dynamic section: %s\n' "$label" "$path" >&2
      return 1
    fi
    index=0
    while ((index < dynamic_size)); do
      base=$((dynamic_offset + index))
      if ! read_uint_le "$path" "$base" 8 dynamic_tag ||
        ! read_uint_le "$path" $((base + 8)) 8 dynamic_value; then
        printf '%s has a malformed dynamic section: %s\n' "$label" "$path" >&2
        return 1
      fi
      if ((dynamic_tag == 0)); then
        dynamic_terminated=1
        break
      fi
      if ((dynamic_tag == 1879048187 && (dynamic_value & 134217728) != 0)); then
        has_pie_flag=1
      fi
      index=$((index + 16))
    done
    if ((dynamic_terminated == 0 || has_pie_flag == 0)); then
      printf '%s is ET_DYN without DF_1_PIE: %s\n' "$label" "$path" >&2
      return 1
    fi
  fi
}

verify_squashfs_payload() {
  local path="$1" offset file_size magic compression major minor bytes_used

  offset="$(wc -c <"$runtime")" || return 1
  file_size="$(wc -c <"$path")" || return 1
  if ((offset > file_size || file_size - offset < 96)); then
    printf 'AppImage has no complete SquashFS superblock: %s\n' "$path" >&2
    return 1
  fi
  magic="$(od -An -tx1 -j "$offset" -N4 "$path" | tr -d ' \n')" || return 1
  if ! read_uint_le "$path" $((offset + 20)) 2 compression ||
    ! read_uint_le "$path" $((offset + 28)) 2 major ||
    ! read_uint_le "$path" $((offset + 30)) 2 minor ||
    ! read_uint_le "$path" $((offset + 40)) 8 bytes_used; then
    return 1
  fi
  if [[ "$magic" != 68737173 ]] ||
    ((compression != 1 || major != 4 || minor != 0 || bytes_used < 96 || bytes_used > file_size - offset)); then
    printf 'AppImage has an invalid, truncated or non-gzip SquashFS payload: %s\n' "$path" >&2
    return 1
  fi
}

(($# == 3)) || die "usage: $0 <linux-x64|linux-arm64> <binary> <output>"
platform="$1"
binary="$2"
output="$3"

case "$platform" in
  linux-x64)
    arch=x86_64
    elf_machine=62
    runtime_override="${APPIMAGE_RUNTIME_X86_64:-}"
    runtime_sha=2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d
    ;;
  linux-arm64)
    arch=aarch64
    elf_machine=183
    runtime_override="${APPIMAGE_RUNTIME_AARCH64:-}"
    runtime_sha=00cbdfcf917cc6c0ff6d3347d59e0ca1f7f45a6df1a428a0d6d8a78664d87444
    ;;
  *) die "unsupported platform: $platform" ;;
esac

[[ -f "$binary" ]] || die "missing binary: $binary"
mkdir -p "$(dirname "$output")"
binary="$(cd "$(dirname "$binary")" && pwd)/$(basename "$binary")"
output_dir="$(cd "$(dirname "$output")" && pwd)"
output="$output_dir/$(basename "$output")"
[[ "$binary" != "$output" ]] || die "input and output must differ"
verify_elf_architecture "$binary" "input binary" || exit 1

cache_dir="${APPIMAGE_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/landstrip/appimage}"
runtime="${runtime_override:-$cache_dir/runtime-20251108-$arch}"
if [[ -z "$runtime_override" ]]; then
  download_verified \
    "https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-$arch" \
    "$runtime_sha" "$runtime"
else
  [[ -f "$runtime" ]] || die "missing runtime file: $runtime"
fi
runtime="$(cd "$(dirname "$runtime")" && pwd)/$(basename "$runtime")"

runner=direct
if [[ -n "${MKSQUASHFS:-}" || "$(uname -s)" == Linux ]]; then
  mksquashfs="$(command -v "${MKSQUASHFS:-mksquashfs}" 2>/dev/null)" \
    || die "required command not found: ${MKSQUASHFS:-mksquashfs} (install squashfs-tools)"
else
  case "$(uname -m)" in
    x86_64|amd64) container_platform=linux/amd64 ;;
    aarch64|arm64) container_platform=linux/arm64 ;;
    *) die "unsupported build architecture: $(uname -m)" ;;
  esac
  if [[ -n "${CONTAINER:-}" && "${CONTAINER:-}" != docker ]]; then
    command -v "$CONTAINER" >/dev/null 2>&1 || die "required command not found: $CONTAINER"
    container_cmd="$CONTAINER"
  elif command -v docker >/dev/null 2>&1; then
    container_cmd=docker
  elif command -v container >/dev/null 2>&1; then
    container_cmd=container
  elif command -v podman >/dev/null 2>&1; then
    container_cmd=podman
  else
    die "required command not found: docker or container"
  fi
  runner=container
fi

appdir="$(mktemp -d "$output_dir/.landstrip-appdir.XXXXXX")"
payload="$appdir.squashfs"
trap 'rm -rf "$appdir"; rm -f "$payload"' EXIT
mkdir -p "$appdir/usr/bin" "$appdir/usr/share/licenses/landstrip"
cp "$binary" "$appdir/usr/bin/landstrip"
chmod 755 "$appdir/usr/bin/landstrip"
ln -s usr/bin/landstrip "$appdir/AppRun"
cp "$(dirname "${BASH_SOURCE[0]}")/../LICENSE" "$appdir/usr/share/licenses/landstrip/LICENSE"
cp "$(dirname "${BASH_SOURCE[0]}")/appimage-runtime.LICENSE" \
  "$appdir/usr/share/licenses/landstrip/AppImage-runtime.LICENSE"
cat >"$appdir/landstrip.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=landstrip
Exec=landstrip
Icon=landstrip
Categories=Development;
Terminal=true
EOF
base64 -d >"$appdir/landstrip.png" <<'EOF'
iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==
EOF
ln -s landstrip.png "$appdir/.DirIcon"
rm -f "$output"

# appimagetool 1.9.1 bundles a Zstandard-only compressor. Build gzip SquashFS
# directly: both the pinned runtime and older AppImageLauncher support zlib.
if [[ "$runner" == direct ]]; then
  "$mksquashfs" "$appdir" "$payload" -comp gzip -noappend -all-root
else
  container_args=()
  if [[ -n "${CONTAINER_CPUS:-}" ]]; then
    container_args+=(--cpus "$CONTAINER_CPUS")
  fi
  if [[ -n "${CONTAINER_MEMORY:-}" ]]; then
    container_args+=(--memory "$CONTAINER_MEMORY")
  fi
  "$container_cmd" run --rm --platform "$container_platform" \
    "${container_args[@]}" \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    -e OUTPUT_NAME="$(basename "$payload")" \
    -v "$appdir:/AppDir:ro" \
    -v "$output_dir:/out" \
    alpine:3.22 sh -ceu '
      apk add --no-cache squashfs-tools >/dev/null
      mksquashfs /AppDir "/out/$OUTPUT_NAME" -comp gzip -noappend -all-root
      chown "$HOST_UID:$HOST_GID" "/out/$OUTPUT_NAME"
    '
fi

[[ -f "$payload" ]] || die "mksquashfs did not create $payload"
cat "$runtime" "$payload" >"$output"
if ! is_type2_appimage "$output"; then
  rm -f "$output"
  die "not a type-2 AppImage: $output"
fi
if ! verify_elf_architecture "$output" "AppImage" || ! verify_squashfs_payload "$output"; then
  rm -f "$output"
  exit 1
fi
chmod 755 "$output"
