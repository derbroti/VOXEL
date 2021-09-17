#!/bin/bash
set -euo pipefail

echo "------------------------------"
echo "generating certificates"
echo "------------------------------"

cd chrome/src/net/tools/quic/certs
./generate-certs.sh

if [[ ! -d "$HOME/.pki/nssdb" ]]
then
	echo "------------------------------"
	echo "creating certificate db"
	echo "------------------------------"
	
	mkdir -p "$HOME/.pki/nssdb"
	certutil -N -d "$HOME/.pki/nssdb" --empty-password
fi

if certutil -d "sql:$HOME/.pki/nssdb" -L -n quic-chrome > /dev/null 2>&1;
then
	echo "------------------------------"
	echo "deleting previous quic-chrome certificate from db"
	echo "------------------------------"
	certutil -d "sql:$HOME/.pki/nssdb" -D -n quic-chrome
fi

echo "------------------------------"
echo "adding quic-chrome certificate to db"
echo "------------------------------"

certutil -d "sql:$HOME/.pki/nssdb" -A -t "C,," -n quic-chrome \
	-i out/2048-sha256-root.pem
