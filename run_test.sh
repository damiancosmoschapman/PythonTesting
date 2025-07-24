#!/bin/bash

# Simple test runner
# Usage: ./run_test.sh [proxy_host] [proxy_port]

PROXY_HOST=${1:-localhost}
PROXY_PORT=${2:-8080}

echo "Testing proxy at $PROXY_HOST:$PROXY_PORT"

python3 proxy_tester.py \
    --proxy-host $PROXY_HOST \
    --proxy-port $PROXY_PORT \
    --malicious-urls malicious_urls.txt \
    --benign-urls benign_urls.txt \
    --test-type both \
    --workers 10 \
    --duration 60 \
    --target-rps 50
