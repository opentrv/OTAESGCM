#!/bin/sh
# Note: Should be run from project root.

# exit on first failure
set -e

# Go to Debug dir
cd Debug

# Make project
make all -j3

# Run tests
gtpp.py ./OTAESGCM
