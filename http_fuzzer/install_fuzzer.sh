#!/bin/bash

# This script creates the virtual environment to fuzz port 80
# of discovered IPs

set -e

# Required system packages
REQUIRED_PACKAGES=(python3-dev python3-virtualenv)

echo "[+] Installing required packages..."
sudo apt update || true
sudo apt install -y "${REQUIRED_PACKAGES[@]}"

# Define paths
rootPath="$(dirname "$(realpath "$0")")"
envPath="$rootPath/crawlEnv"


# Create virtual environment
echo "[+] Creating virtual environment..."
virtualenv "$envPath" --python=python3

# Activate and install Python dependencies
echo "[+] Installing Python dependencies..."
source "$envPath/bin/activate"
pip install -r "$rootPath/requirements.txt"
deactivate
