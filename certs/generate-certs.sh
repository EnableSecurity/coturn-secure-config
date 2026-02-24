#!/bin/bash
# Generate self-signed certificates for testing coturn TLS
# NOT for production use

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

openssl req -x509 -newkey rsa:2048 \
  -keyout "$SCRIPT_DIR/privkey.pem" \
  -out "$SCRIPT_DIR/cert.pem" \
  -days 365 -nodes \
  -subj "/CN=turn.example.com"

chmod 644 "$SCRIPT_DIR/cert.pem"
chmod 600 "$SCRIPT_DIR/privkey.pem"

echo "Certificates generated in $SCRIPT_DIR/"
