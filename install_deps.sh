#!/bin/bash

# Exit on error, undefined variable, or error in a pipeline
set -ueo pipefail


<<<<<<< HEAD
echo -e "\n\n >> Installing dependent libraries...\n\n"
=======
echo -e "\n\n >> Installing python3 tools...\n\n"
sudo apt install -y \
    python3-pip \
    python3-setuptools \
    python3-pyscard

echo -e "\n\n >> Installing depending libraries...\n\n"
>>>>>>> f88e926 (included previous requirements, which I might've missed and improved the README.md)
# libpcsclite required by pyscard; the rest are useful for testing with physical smart cards
sudo apt install -y \
    libpcsclite-dev \
    pcscd \
    pcsc-tools


echo -e "\n\n >> Creating and activating a Python virtual environment...\n\n"
python3 -m venv .venv
source .venv/bin/activate


echo -e "\n\n >> Installing Python dependencies...\n\n"
pip3 install -r requirements.txt


echo -e "\n\n >> Testing SWU Emulator... if you see the help message, it mostly worked\n\n"
python3 swu_emulator.py -h


echo -e "\n\n >> Setting capabilities to allow binding to low-numbered ports and raw sockets, without sudo...\n\n"
python_bin=$(readlink -f .venv/bin/python3)
sudo setcap 'cap_net_bind_service,cap_net_raw=+ep' "$python_bin"
getcap "$python_bin"
