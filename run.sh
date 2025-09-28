#!/bin/bash

source .venv/bin/activate

# Because this would listen on port 500 (<1024) and open a socket for ESP, either run this as root, or give capabilities
# to the python binary in the venv (done in install_deps.sh)
python3 swu_emulator.py \
     --imsi=001011234567890 \
     --ki=000102030405060708090a0b0c0d0e0f \
     --op=00112233445566778899aabbccddeeff \
     --dest=192.168.64.1
