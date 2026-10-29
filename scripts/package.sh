#!/usr/bin/env bash
# Package release binaries into dist/ with stable names and checksums.
#
#   ./scripts/package.sh aarch64-apple-darwin
#   ./scripts/package.sh all            # every target that has been built
#
# Windows targets get .zip (users expect it), everything else .tar.gz.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

ALL_TARGETS=(
  aarch64-apple-darwin
  x86_64-apple-darwin
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-musl
  x86_64-pc-windows-gnu
)

version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
[ -n "$version" ] || { echo "cannot read version from Cargo.toml" >&2; exit 1; }

pack() {
  local target="$1"
  local bin="target/$target/release/fairlead"
  [ -f "${bin}.exe" ] && bin="${bin}.exe"
  if [ ! -f "$bin" ]; then
    echo "skip $target (not built)" >&2
    return 0
  fi

  local name="fairlead-$version-$target"
  local stage="dist/$name"
  rm -rf "$stage"
  mkdir -p "$stage/docs" "$stage/deploy"

  if [[ "$target" == *windows* ]]; then
    cp "$bin" "$stage/fairlead.exe"
  else
    cp "$bin" "$stage/fairlead"
    chmod +x "$stage/fairlead"
  fi
  cp README.md CHANGELOG.md LICENSE "$stage/"
  cp docs/ARCHITECTURE.md docs/RELEASE.md docs/DECISIONS.md docs/PRD.md "$stage/docs/"
  cp -r deploy/nginx deploy/systemd deploy/host.toml deploy/agent.toml \
        deploy/docker-compose.yml deploy/Dockerfile "$stage/deploy/"

  if [[ "$target" == *windows* ]] && command -v zip >/dev/null 2>&1; then
    (cd dist && rm -f "$name.zip" && zip -qr "$name.zip" "$name")
    rm -rf "$stage"
    echo "dist/$name.zip"
  else
    tar -czf "dist/$name.tar.gz" -C dist "$name"
    rm -rf "$stage"
    echo "dist/$name.tar.gz"
  fi
}

mkdir -p dist
targets=("$@")
[ "${targets[0]:-}" = "all" ] && targets=("${ALL_TARGETS[@]}")
[ ${#targets[@]} -gt 0 ] || { echo "usage: package.sh <target>|all [target...]" >&2; exit 1; }

for t in "${targets[@]}"; do
  pack "$t"
done

# One combined checksum file for the release page.
(cd dist && rm -f SHA256SUMS
 if command -v sha256sum >/dev/null 2>&1; then
   for f in fairlead-*"$version"*.{tar.gz,zip}; do
     [ -f "$f" ] && sha256sum "$f" >> SHA256SUMS
   done
 else
   for f in fairlead-*"$version"*.{tar.gz,zip}; do
     [ -f "$f" ] && shasum -a 256 "$f" >> SHA256SUMS
   done
 fi
 sort -o SHA256SUMS SHA256SUMS
 echo "dist/SHA256SUMS")
