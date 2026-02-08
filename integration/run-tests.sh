#!/usr/bin/env bash
# Run integration tests for nomad-driver-cri
#
# Usage:
#   ./integration/run-tests.sh              # Run all integration tests (will use sudo internally)
#   ./integration/run-tests.sh -v           # Verbose output
#   ./integration/run-tests.sh -run Exec    # Run specific test
#
# Note: This script should be run from within 'nix develop' shell

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Check for required binaries
check_binaries() {
    local missing=()
    for bin in containerd nomad go; do
        if ! command -v "$bin" &> /dev/null; then
            missing+=("$bin")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing binaries: ${missing[*]}"
        echo ""
        echo "Please run this script from within 'nix develop' shell:"
        echo "  nix develop"
        echo "  ./integration/run-tests.sh"
        exit 1
    fi
}

# Store paths to binaries before potentially escalating to root
# This preserves the nix shell paths when using sudo
store_binary_paths() {
    export CONTAINERD_BIN="$(command -v containerd)"
    export NOMAD_BIN="$(command -v nomad)"
    export GO_BIN="$(command -v go)"
    export CTR_BIN="$(command -v ctr || echo "")"
    export CRICTL_BIN="$(command -v crictl || echo "")"

    # Also store the PATH so we can use other nix tools
    export PRESERVED_PATH="$PATH"
}

run_as_root() {
    # Build the plugin if needed
    PLUGIN_PATH="${PROJECT_DIR}/plugins/nomad-driver-cri"
    if [[ ! -f "$PLUGIN_PATH" ]]; then
        log "Building plugin..."
        cd "$PROJECT_DIR"
        "$GO_BIN" build -o "$PLUGIN_PATH" .
    fi

    export PLUGIN_PATH

    # Use preserved PATH and stored binary paths
    export PATH="$PRESERVED_PATH"

    # Check if containerd is running
    if [[ ! -S /run/containerd/containerd.sock ]]; then
        log "Starting containerd..."
        "$CONTAINERD_BIN" &
        CONTAINERD_PID=$!
        trap "kill $CONTAINERD_PID 2>/dev/null || true" EXIT

        # Wait for socket
        for i in {1..30}; do
            if [[ -S /run/containerd/containerd.sock ]]; then
                log "containerd is ready"
                break
            fi
            sleep 1
        done

        if [[ ! -S /run/containerd/containerd.sock ]]; then
            error "containerd failed to start"
            exit 1
        fi
    else
        log "containerd already running"
    fi

    # Pull test images ahead of time to speed up tests
    if [[ -n "$CTR_BIN" ]]; then
        log "Pulling test images..."
        "$CTR_BIN" images pull docker.io/library/alpine:latest >/dev/null 2>&1 || true
        "$CTR_BIN" images pull docker.io/library/busybox:latest >/dev/null 2>&1 || true
        "$CTR_BIN" images pull docker.io/library/nginx:alpine >/dev/null 2>&1 || true
    fi

    # Run integration tests
    log "Running integration tests..."
    cd "$PROJECT_DIR"

    # Pass through any arguments to go test
    "$GO_BIN" test -v -tags=integration -timeout=10m ./integration/... "$@"

    log "Integration tests completed successfully!"
}

# Main
check_binaries
store_binary_paths

# Check if we're already root
if [[ $EUID -eq 0 ]]; then
    run_as_root "$@"
else
    log "Escalating to root (required for containerd and Nomad)..."
    # Re-run this script as root, preserving our exported variables
    sudo \
        CONTAINERD_BIN="$CONTAINERD_BIN" \
        NOMAD_BIN="$NOMAD_BIN" \
        GO_BIN="$GO_BIN" \
        CTR_BIN="$CTR_BIN" \
        CRICTL_BIN="$CRICTL_BIN" \
        PRESERVED_PATH="$PRESERVED_PATH" \
        PLUGIN_PATH="${PROJECT_DIR}/plugins/nomad-driver-cri" \
        "$0" "$@"
fi
