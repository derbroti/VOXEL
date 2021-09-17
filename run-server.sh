#!/bin/bash
set -euo pipefail

if [ ! $# -eq 1 ]
then
    echo "usage: $0 <path/to/video/dir>"
    exit 1
fi

readonly PORT=6121
readonly CERT_DIR=chrome/src/net/tools/quic/certs/out
CACHE_DIR="${1%/}"

./chrome/src/out/Release/quic_server \
    --certificate_file="$CERT_DIR/leaf_cert.pem" \
    --key_file="$CERT_DIR/leaf_cert.pkcs8" \
    --port="$PORT" \
    --quic_response_cache_dir="$CACHE_DIR"

