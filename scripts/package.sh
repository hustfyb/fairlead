#!/usr/bin/env bash
# Package one target into dist/frplike-<version>-<target>.tar.gz + sha256.
#
#   ./scripts/package.sh aarch64-apple-darwin
#   ./scripts/package.sh x86_64-unknown-linux-musl 0.1.0
set -euo pipefail

target="${1:?usage: package.sh <target-triple> [version]}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

version="${2:-$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)}"
[ -n "$version" ] || { echo "cannot read version from Cargo.toml" >&2; exit 1; }

bin="target/$target/release/frplike"
[ -f "$bin" ] || bin="target/release/frplike"
[ -f "${bin}.exe" ] && bin="${bin}.exe"
[ -f "$bin" ] || { echo "binary not found: $bin" >&2; exit 1; }

name="frplike-$version-$target"
out="dist/$name"
rm -rf "$out"
mkdir -p "$out/docs" "$out/deploy"

cp "$bin" "$out/frplike"
chmod +x "$out/frplike"
cp README.md LICENSE "$out/" 2>/dev/null || true
cp docs/ARCHITECTURE.md docs/RELEASE.md docs/DECISIONS.md "$out/docs/"
cp -r deploy/nginx deploy/systemd deploy/host.toml deploy/agent.toml deploy/docker-compose.yml deploy/Dockerfile "$out/deploy/"

mkdir -p dist
tar -czf "dist/$name.tar.gz" -C dist "$name"
rm -rf "$out"

if command -v sha256sum >/dev/null 2>&1; then
  (cd dist && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
else
  (cd dist && shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256")
fi
echo "dist/$name.tar.gz"
