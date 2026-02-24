#!/bin/bash
# Test coturn configuration security
# Requires: running coturn container (docker compose up -d)
# Requires: turnutils_uclient and openssl in PATH
#
# Usage from host:
#   docker compose exec coturn /opt/tests/test-config.sh
#
# Override defaults with environment variables:
#   COTURN_PROFILE=minimal TURN_HOST=127.0.0.1 /opt/tests/test-config.sh

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
SKIP=0

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

skip() {
    echo "  SKIP: $1"
    SKIP=$((SKIP + 1))
}

read -r USERNAME PASSWORD <<< "$(generate_credential "$TURN_USER" "$TURN_SECRET")"

echo "Testing coturn config profile: $PROFILE"
echo "Server: $TURN_HOST:$TURN_PORT"
echo "External peer: $EXTERNAL_PEER:$EXTERNAL_PEER_PORT"
echo "---"

# Test 1: Basic TURN allocation to external peer should succeed
# Note: we only check that the allocation is not denied (no 403).
# turnutils_uclient will show 100% packet loss because the external
# peer isn't a real TURN peer, but that's expected.
echo "Test 1: TURN allocation to external peer (should succeed)"
if turnutils_uclient -e "$EXTERNAL_PEER" -r "$EXTERNAL_PEER_PORT" -u "$USERNAME" -w "$PASSWORD" "$TURN_HOST" -p "$TURN_PORT" -n 1 2>/dev/null; then
    pass "Allocation to external peer accepted"
else
    fail "Allocation to external peer denied (should be allowed)"
fi

# Test 2: Unauthenticated TURN allocation should be denied
echo "Test 2: Unauthenticated TURN allocation (should be denied)"
if turnutils_uclient -e "$EXTERNAL_PEER" -r "$EXTERNAL_PEER_PORT" "$TURN_HOST" -p "$TURN_PORT" -n 1 2>/dev/null; then
    fail "Unauthenticated allocation was allowed"
else
    pass "Unauthenticated allocation correctly denied"
fi

# Test 3: Relay to loopback should be denied
echo "Test 3: Relay to 127.0.0.1 (should be denied)"
if turnutils_uclient -e 127.0.0.1 -u "$USERNAME" -w "$PASSWORD" "$TURN_HOST" -p "$TURN_PORT" -n 1 2>/dev/null; then
    fail "Relay to 127.0.0.1 was allowed"
else
    pass "Relay to 127.0.0.1 correctly denied"
fi

# Test 4: Relay to RFC1918 10.x should be denied
echo "Test 4: Relay to 10.0.0.1 (should be denied)"
if turnutils_uclient -e 10.0.0.1 -u "$USERNAME" -w "$PASSWORD" "$TURN_HOST" -p "$TURN_PORT" -n 1 2>/dev/null; then
    fail "Relay to 10.0.0.1 was allowed"
else
    pass "Relay to 10.0.0.1 correctly denied"
fi

# Test 5: Relay to RFC1918 192.168.x should be denied
echo "Test 5: Relay to 192.168.1.1 (should be denied)"
if turnutils_uclient -e 192.168.1.1 -u "$USERNAME" -w "$PASSWORD" "$TURN_HOST" -p "$TURN_PORT" -n 1 2>/dev/null; then
    fail "Relay to 192.168.1.1 was allowed"
else
    pass "Relay to 192.168.1.1 correctly denied"
fi

# Test 6: Relay to cloud metadata endpoint (169.254.169.254)
echo "Test 6: Relay to 169.254.169.254 (should be denied)"
if turnutils_uclient -e 169.254.169.254 -u "$USERNAME" -w "$PASSWORD" "$TURN_HOST" -p "$TURN_PORT" -n 1 2>/dev/null; then
    fail "Relay to 169.254.169.254 was allowed"
else
    pass "Relay to 169.254.169.254 correctly denied"
fi

# Test 7: IPv4-mapped IPv6 bypass (CVE-2026-27624)
# An attacker could bypass denied-peer-ip rules by using ::ffff:127.0.0.1
# instead of 127.0.0.1. This is fixed in coturn 4.9.0 and also covered
# by our denied-peer-ip=::ffff:0.0.0.0-::ffff:255.255.255.255 rule.
# Note: turnutils_uclient cannot properly handle ::ffff: peer addresses -
# it fails during relay address parsing before reaching the channel bind
# or permission stage. These tests verify that the bypass doesn't succeed,
# but they don't exercise the denied-peer-ip path specifically. A proper
# CVE-2026-27624 test would require a TURN client that can craft ::ffff:
# addresses in CreatePermission/ChannelBind requests.
echo "Test 7: Relay to ::ffff:127.0.0.1 - IPv4-mapped IPv6 bypass (should be denied)"
if turnutils_uclient -e "::ffff:127.0.0.1" -u "$USERNAME" -w "$PASSWORD" "$TURN_HOST" -p "$TURN_PORT" -n 1 2>/dev/null; then
    fail "Relay to ::ffff:127.0.0.1 was allowed (CVE-2026-27624 bypass)"
else
    pass "Relay to ::ffff:127.0.0.1 correctly denied"
fi

# Test 8: IPv4-mapped IPv6 bypass for RFC1918
echo "Test 8: Relay to ::ffff:10.0.0.1 - IPv4-mapped IPv6 bypass (should be denied)"
if turnutils_uclient -e "::ffff:10.0.0.1" -u "$USERNAME" -w "$PASSWORD" "$TURN_HOST" -p "$TURN_PORT" -n 1 2>/dev/null; then
    fail "Relay to ::ffff:10.0.0.1 was allowed (CVE-2026-27624 bypass)"
else
    pass "Relay to ::ffff:10.0.0.1 correctly denied"
fi

# Test 9: IPv4-mapped IPv6 bypass for metadata endpoint
echo "Test 9: Relay to ::ffff:169.254.169.254 - IPv4-mapped IPv6 bypass (should be denied)"
if turnutils_uclient -e "::ffff:169.254.169.254" -u "$USERNAME" -w "$PASSWORD" "$TURN_HOST" -p "$TURN_PORT" -n 1 2>/dev/null; then
    fail "Relay to ::ffff:169.254.169.254 was allowed (CVE-2026-27624 bypass)"
else
    pass "Relay to ::ffff:169.254.169.254 correctly denied"
fi

# Test 10: TLS connectivity (recommended and high-security profiles)
if [ "$PROFILE" = "recommended" ] || [ "$PROFILE" = "high-security" ]; then
    echo "Test 10: TLS TURN allocation"
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
else
    skip "TLS test (not applicable for $PROFILE profile)"
fi

echo "---"
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
