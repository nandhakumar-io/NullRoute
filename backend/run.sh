#!/usr/bin/env bash
# Quick wrapper to run the FastAPI backend with native NixOS C++ bindings for Pandas/PyBatfish.
echo "Binding NixOS libstdc++.so.6 using nix-build..."
export LD_LIBRARY_PATH=$(nix-build '<nixpkgs>' -A stdenv.cc.cc.lib --no-out-link)/lib:$LD_LIBRARY_PATH

echo "Activating virtualenv and starting Uvicorn..."
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
