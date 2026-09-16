#!/bin/bash

if [ "$(uname -s)" = Darwin ]; then
    echo "On macOS the TUN path needs Linux. Use ./run-lima.sh" >&2
    exit 1
fi

# shellcheck disable=SC1091
source "${SWU_VENV:-.venv}/bin/activate"

# Because this would listen on port 500 (<1024) and open a socket for ESP, either run this as root, or give capabilities
# to the python binary in the venv (done in install_deps.sh)
if [ -n "${SWU_CONFIG:-}" ]; then
    CONFIG="$SWU_CONFIG"
elif [ -f swu.lab.yaml ]; then
    CONFIG=swu.lab.yaml
else
    CONFIG=swu.yaml
fi
python3 swu_emulator.py --config "$CONFIG" "$@"
