#!/bin/bash
# Test coturn configuration security
# Requires: running coturn container (docker compose up -d)
# Requires: turnutils_uclient and openssl in PATH
#
# Run from inside the coturn container or install turnutils_uclient locally:
#   docker compose exec coturn /path/to/tests/test-config.sh

set -euo pipefail

TURN_HOST="${TURN_HOST:-127.0.0.1}"
TURN_PORT="${TURN_PORT:-3478}"
TURN_SECRET="testing-secret-do-not-use-in-production"
TURN_USER="test"
PROFILE="${COTURN_PROFILE:-recommended}"

# External peer for allocation tests (must not be in denied-peer-ip ranges)
EXTERNAL_PEER="${EXTERNAL_PEER:-8.8.8.8}"
EXTERNAL_PEER_PORT="${EXTERNAL_PEER_PORT:-19302}"

PASS=0
FAIL=0

# Generate TURN credential (HMAC-based as per RFC 5389 / use-auth-secret)
generate_credential() {
    local user="$1"
    local secret="$2"
    local timestamp
    timestamp=$(($(date +%s) + 86400))
    local username="${timestamp}:${user}"
    local password
    password=$(echo -n "$username" | openssl dgst -sha1 -hmac "$secret" -binary | base64)
    echo "$username" "$password"
}

pass() {
    echo "  PASS: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  FAIL: $1"
    FAIL=$((FAIL + 1))
}

read -r USERNAME PASSWORD <<< "$(generate_credential "$TURN_USER" "$TURN_SECRET")"

echo "Testing coturn config profile: $PROFILE"
echo "Server: $TURN_HOST:$TURN_PORT"
echo "External peer: $EXTERNAL_PEER:$EXTERNAL_PEER_PORT"
echo "---"

# Test 1: Basic TURN allocation to external peer should work
echo "Test 1: TURN allocation to external peer"
if turnutils_uclient -e "$EXTERNAL_PEER" -r "$EXTERNAL_PEER_PORT" -u "$USERNAME" -w "$PASSWORD" "$TURN_HOST" -p "$TURN_PORT" -n 1 2>/dev/null; then
    pass "TURN allocation succeeded"
else
    fail "TURN allocation failed"
fi

# Test 2: Relay to loopback should be denied
echo "Test 2: Relay to 127.0.0.1 (should be denied)"
if turnutils_uclient -e 127.0.0.1 -u "$USERNAME" -w "$PASSWORD" "$TURN_HOST" -p "$TURN_PORT" -n 1 2>/dev/null; then
    fail "Relay to 127.0.0.1 was allowed (should be denied)"
else
    pass "Relay to 127.0.0.1 correctly denied"
fi

# Test 3: Relay to RFC1918 should be denied
echo "Test 3: Relay to 10.0.0.1 (should be denied)"
if turnutils_uclient -e 10.0.0.1 -u "$USERNAME" -w "$PASSWORD" "$TURN_HOST" -p "$TURN_PORT" -n 1 2>/dev/null; then
    fail "Relay to 10.0.0.1 was allowed (should be denied)"
else
    pass "Relay to 10.0.0.1 correctly denied"
fi

# Test 4: Relay to 192.168.x should be denied
echo "Test 4: Relay to 192.168.1.1 (should be denied)"
if turnutils_uclient -e 192.168.1.1 -u "$USERNAME" -w "$PASSWORD" "$TURN_HOST" -p "$TURN_PORT" -n 1 2>/dev/null; then
    fail "Relay to 192.168.1.1 was allowed (should be denied)"
else
    pass "Relay to 192.168.1.1 correctly denied"
fi

# Test 5: TLS connectivity (recommended and high-security profiles)
if [ "$PROFILE" = "recommended" ] || [ "$PROFILE" = "high-security" ]; then
    echo "Test 5: TLS TURN allocation"
    # high-security uses TLS 1.3 only (no-tlsv1_2), which requires TCP+TLS (-t)
    # since DTLS 1.3 is not yet widely available
    TLS_FLAGS="-S"
    if [ "$PROFILE" = "high-security" ]; then
        TLS_FLAGS="-S -t"
    fi
    if turnutils_uclient $TLS_FLAGS -e "$EXTERNAL_PEER" -r "$EXTERNAL_PEER_PORT" -u "$USERNAME" -w "$PASSWORD" "$TURN_HOST" -p 5349 -n 1 2>/dev/null; then
        pass "TLS TURN allocation succeeded"
    else
        fail "TLS TURN allocation failed"
    fi
fi

echo "---"
echo "Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
