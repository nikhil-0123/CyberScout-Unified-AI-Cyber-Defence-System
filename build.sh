#!/usr/bin/env bash
# Render & CI build script for CyberScout backend

set -o errexit

python -m pip install --upgrade pip
pip install -r requirements.txt

echo "CyberScout Backend build completed successfully!"
