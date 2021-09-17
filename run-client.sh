#!/bin/bash
set -euo pipefail

if [ ! $# -eq 3 ]
then
    echo "usage: $0 <MPD> <log-output> <video-output>"
    exit 1
fi

readonly HOST=127.0.0.1
readonly PORT=6121
readonly BUF_SIZE_MS=8000
readonly ABR=bpp
MPD="$1"
LOG_OUTPUT="$2"
VIDEO_OUTPUT="$3"
REQUEST="https://www.example.org/$MPD"

echo "Starting client..."
echo "Connecting to $HOST:$PORT"
echo "Requesting $REQUEST"
echo "Writing video to $VIDEO_OUTPUT"
echo "Writing log to $LOG_OUTPUT"

./chrome/src/out/Release/quic_client \
    -q \
    --host="$HOST" \
    --port="$PORT" \
    --abr_buf="$BUF_SIZE_MS" \
    --abr="$ABR" \
    "$REQUEST" \
    1> "$VIDEO_OUTPUT" \
    2> "$LOG_OUTPUT"

