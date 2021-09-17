#!/bin/bash
set -euo pipefail
# Required for ninja executable
export PATH="$PATH:$(pwd)/chrome/depot_tools"
./update-mod-links.sh
cp ninja-files/* chrome/src/out/Release/obj/net/
echo "const char *gitversion = \"CoNext 2021\";" > chrome/src/net/tools/quic/gitversion.cc
ninja -C chrome/src/out/Release quic_client quic_server
rm chrome/src/net/tools/quic/gitversion.cc
