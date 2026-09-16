#!/bin/bash

# Exit on error, undefined variable, or error in a pipeline
set -ueo pipefail

cd "$(dirname "$0")"

WITH_USIM=0
for arg in "$@"; do
    case "$arg" in
        --with-usim)
            WITH_USIM=1
            ;;
        -h|--help)
            cat <<'EOF'
Usage: ./install_deps.sh [--with-usim]

Default (Ubuntu/Debian): venv + Milenage deps. Enough for --imsi/--ki/--op
or --opc, with no SIM reader.

  --with-usim   Also install PC/SC (libpcsclite, pcscd, pyscard, card)
                for a physical smartcard reader.

The venv interpreter is copied (not symlinked) so setcap is applied to
the venv python, not the system python3.

SWU_VENV overrides the venv path (default .venv). Lima uses
~/.cache/swu-venv on the VM disk so a Darwin .venv is not reused.
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            echo "Usage: $0 [--with-usim]" >&2
            exit 1
            ;;
    esac
done

if ! command -v apt-get >/dev/null 2>&1; then
    echo "This script targets Ubuntu/Debian (apt-get). Run it on a Linux lab host." >&2
    exit 1
fi

echo -e "\n\n >> Updating apt and installing Python build tools...\n\n"
sudo apt-get update
sudo apt-get install -y \
    python3-pip \
    python3-setuptools \
    python3-venv \
    python3-dev \
    build-essential \
    swig \
    git \
    libcap2-bin \
    iproute2 \
    net-tools

if [ "$WITH_USIM" -eq 1 ]; then
    echo -e "\n\n >> Installing PC/SC stack for smartcard readers...\n\n"
    sudo apt-get install -y \
        libpcsclite-dev \
        pcscd \
        pcsc-tools
fi

VENV_DIR="${SWU_VENV:-.venv}"

echo -e "\n\n >> Creating and activating a Python virtual environment...\n\n"
python3 -m venv --copies "$VENV_DIR"
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo -e "\n\n >> Installing Python dependencies...\n\n"
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
if [ "$WITH_USIM" -eq 1 ]; then
    python3 -m pip install -r requirements-usim.txt
fi

echo -e "\n\n >> Testing SWU Emulator... if you see the help message, it mostly worked\n\n"
python3 swu_emulator.py -h

echo -e "\n\n >> Setting capabilities to allow binding to low-numbered ports and raw sockets, without sudo...\n\n"
python_bin="$(python3 -c 'import sys; print(sys.executable)')"
venv_root="$(cd "$VENV_DIR" && pwd)"
case "$python_bin" in
    "$venv_root"/*)
        ;;
    *)
        echo "Refusing to setcap '$python_bin' (not inside $venv_root)." >&2
        echo "Recreate the venv with: python3 -m venv --copies $VENV_DIR" >&2
        exit 1
        ;;
esac
caps='cap_net_bind_service,cap_net_raw,cap_net_admin=+ep'
sudo setcap "$caps" "$python_bin"
# venv --copies makes python and python3 separate binaries
for extra in python python3; do
    extra_bin="$venv_root/bin/$extra"
    if [ -f "$extra_bin" ] && [ "$extra_bin" != "$python_bin" ]; then
        sudo setcap "$caps" "$extra_bin"
    fi
done
getcap "$venv_root"/bin/python "$venv_root"/bin/python3 2>/dev/null || getcap "$python_bin"
