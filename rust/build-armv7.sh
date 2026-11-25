#!/bin/sh
# Cross-compile static ARMv7 (musl soft-float EABI5) binary for ZTE / Huawei embedded routers
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET="armv7-unknown-linux-musleabi"

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo "[*] Building $TARGET via Docker cross-compile container..."
    docker build -f "$SCRIPT_DIR/Dockerfile.cross" -t homeshield-cross "$SCRIPT_DIR"
    mkdir -p "$SCRIPT_DIR/target/$TARGET/release"
    docker run --rm -v "$SCRIPT_DIR:/work" -w /work homeshield-cross \
        cargo build --release --target "$TARGET" -p homeshield-daemon
    ls -lh "$SCRIPT_DIR/target/$TARGET/release/homeshield-daemon"
    exit 0
fi

if command -v cargo-zigbuild >/dev/null 2>&1 && command -v zig >/dev/null 2>&1; then
    echo "[*] Building $TARGET via cargo-zigbuild..."
    cd "$SCRIPT_DIR"
    cargo zigbuild --release --target "$TARGET" -p homeshield-daemon
    ls -lh "$SCRIPT_DIR/target/$TARGET/release/homeshield-daemon"
    exit 0
fi

echo "[-] Neither a running Docker daemon nor cargo-zigbuild/zig was found."
echo "    To build natively for host instead, run: cd rust && cargo build --release"
exit 1
