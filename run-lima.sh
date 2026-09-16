#!/bin/bash

# Exit on error, undefined variable, or error in a pipeline
set -ueo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"

EPHEMERAL=0
RUN_TEST=0
NAME=swu

usage() {
    cat <<'EOF'
Usage: ./run-lima.sh [--ephemeral] [--test] [--] [args]

macOS only. Runs the SWu client in a Lima Ubuntu VM (Virtualization.framework).
The TUN stays in the guest. Software AKA works; a USB SIM reader does not.

  --ephemeral   Throwaway instance swu-ephemeral (deleted on exit)
  --test        Run unit tests in the guest (no TUN / no attach)
  --            Following arguments go to swu_emulator.py, or to
                unittest when --test is set

Requires: brew install lima (Lima 2.x)

Uses swu.lab.yaml if present, else swu.yaml. Override with SWU_CONFIG.
Always passes --no-default-route --no-dns so the guest default stays off the TUN.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --ephemeral)
            EPHEMERAL=1
            NAME=swu-ephemeral
            shift
            ;;
        --test)
            RUN_TEST=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Unknown option: $1 (pass emulator args after --)" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [ "$(uname -s)" != Darwin ]; then
    echo "run-lima.sh is for macOS. On Linux use ./install_deps.sh and ./run.sh." >&2
    exit 1
fi

if ! command -v limactl >/dev/null 2>&1; then
    echo "limactl not found. Install Lima: brew install lima" >&2
    exit 1
fi

instance_exists() {
    limactl list -q 2>/dev/null | grep -qx "$1"
}

if [ "$EPHEMERAL" -eq 1 ]; then
    if instance_exists "$NAME"; then
        limactl delete -f "$NAME"
    fi
    trap 'limactl delete -f "$NAME" >/dev/null 2>&1 || true' EXIT
fi

if [ "$RUN_TEST" -eq 0 ]; then
    if [ -n "${SWU_CONFIG:-}" ]; then
        CONFIG="$SWU_CONFIG"
    elif [ -f "$ROOT/swu.lab.yaml" ]; then
        CONFIG=swu.lab.yaml
    else
        CONFIG=swu.yaml
    fi
fi

if instance_exists "$NAME"; then
    limactl start "$NAME"
else
    limactl start --tty=false --name="$NAME" --mount="${ROOT}:w" "$ROOT/lima.yaml"
fi

if [ "$RUN_TEST" -eq 1 ]; then
    if [ $# -eq 0 ]; then
        set -- discover -s . -p 'test_*.py' -v
    fi
    limactl shell "$NAME" -- bash -lc '
        set -euo pipefail
        export SWU_VENV="$HOME/.cache/swu-venv"
        cd "$1"
        if [ ! -x "$SWU_VENV/bin/python3" ]; then
            ./install_deps.sh
        fi
        shift
        exec "$SWU_VENV/bin/python3" -m unittest "$@"
    ' lima "$ROOT" "$@"
    exit $?
fi

limactl shell "$NAME" -- bash -lc '
    set -euo pipefail
    export SWU_VENV="$HOME/.cache/swu-venv"
    cd "$1"
    if [ ! -x "$SWU_VENV/bin/python3" ]; then
        ./install_deps.sh
    fi
    caps='cap_net_bind_service,cap_net_raw,cap_net_admin=+ep'
    for bin in python python3; do
        p="$SWU_VENV/bin/$bin"
        if [ -f "$p" ] && ! getcap "$p" 2>/dev/null | grep -q cap_net_admin; then
            sudo -n setcap "$caps" "$p"
        fi
    done
    if [ ! -e /dev/net/tun ]; then
        sudo -n modprobe tun
    fi
    exec "$SWU_VENV/bin/python3" swu_emulator.py --config "$2" \
        --no-default-route --no-dns "${@:3}"
' lima "$ROOT" "$CONFIG" "$@"
