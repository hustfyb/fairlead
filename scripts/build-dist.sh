#!/usr/bin/env bash
# Build every shipped target with cargo-zigbuild.
#
# Local (macOS/Linux) needs: rustup targets + zig on PATH. If zig is not on PATH
# but the `ziglang` pip package is installed (handy behind a slow network), use it.
#
#   ./scripts/build-dist.sh              # all targets
#   ./scripts/build-dist.sh x86_64-unknown-linux-musl
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

TARGETS=(
  aarch64-apple-darwin
  x86_64-apple-darwin
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-musl
  x86_64-pc-windows-gnu
)

if ! command -v zig >/dev/null 2>&1; then
  if python3 -c 'import ziglang' >/dev/null 2>&1; then
    zigdir="$(python3 -c 'import ziglang, os; print(os.path.dirname(ziglang.__file__))')"
    chmod +x "$zigdir/zig" 2>/dev/null || true
    export PATH="$zigdir:$PATH"
  else
    echo "error: zig not found (brew install zig, or pip install ziglang)" >&2
    exit 1
  fi
fi
echo "zig $(zig version)"

command -v cargo-zigbuild >/dev/null 2>&1 || cargo install cargo-zigbuild --locked

targets=("$@")
[ ${#targets[@]} -eq 0 ] && targets=("${TARGETS[@]}")

for t in "${targets[@]}"; do
  rustup target add "$t" >/dev/null 2>&1 || true
  echo "=== $t"
  cargo zigbuild --release --locked --bin frplike --target "$t"
done

echo "done: $(ls target/*/release/frplike* 2>/dev/null | wc -l | tr -d ' ') binaries"
