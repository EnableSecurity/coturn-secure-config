#!/bin/bash
# Test coturn configuration security
#
# Supports two execution modes:
# 1) Probe-first (recommended): uses turn-probe.py + python3 for deterministic ACL checks.
# 2) Fallback: uses turnutils_uclient where python probe is unavailable.
#
# Usage with docker compose (recommended):
#   docker compose up -d
#   docker compose run --rm test-runner
#
# Test a specific profile:
#   COTURN_PROFILE=high-security docker compose up -d
#   COTURN_PROFILE=high-security docker compose run --rm test-runner
#
# Usage from host (requires python3 and openssl):
#   bash tests/test-config.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TURN_HOST="${TURN_HOST:-127.0.0.1}"
TURN_PORT="${TURN_PORT:-3478}"
TURN_SECRET="${TURN_SECRET:-testing-secret-do-not-use-in-production}"
TURN_USER="${TURN_USER:-test}"
PROFILE="${COTURN_PROFILE:-recommended}"

# External peer for allocation tests (must not be in denied-peer-ip ranges)
EXTERNAL_PEER="${EXTERNAL_PEER:-8.8.8.8}"
EXTERNAL_PEER_PORT="${EXTERNAL_PEER_PORT:-19302}"

PASS=0
FAIL=0
SKIP=0

if [ -f /opt/tests/turn-probe.py ]; then
    PROBE_SCRIPT="/opt/tests/turn-probe.py"
elif [ -f "$SCRIPT_DIR/turn-probe.py" ]; then
    PROBE_SCRIPT="$SCRIPT_DIR/turn-probe.py"
else
    PROBE_SCRIPT=""
fi

HAS_PROBE=0
if command -v python3 >/dev/null 2>&1 && [ -n "$PROBE_SCRIPT" ]; then
    HAS_PROBE=1
fi

HAS_UCLIENT=0
if command -v turnutils_uclient >/dev/null 2>&1; then
    HAS_UCLIENT=1
fi

# Generate TURN credential (HMAC-based as per RFC 5389 / use-auth-secret)
generate_credential() {
    local user="$1"
    local secret="$2"

    if command -v openssl >/dev/null 2>&1; then
        local timestamp username password
        timestamp=$(($(date +%s) + 86400))
        username="${timestamp}:${user}"
        password=$(echo -n "$username" | openssl dgst -sha1 -hmac "$secret" -binary | base64)
        echo "$username" "$password"
        return 0
    fi

    if command -v python3 >/dev/null 2>&1; then
        python3 - "$user" "$secret" <<'PY'
import base64
import hashlib
import hmac
import sys
import time

user = sys.argv[1]
secret = sys.argv[2].encode("utf-8")
username = f"{int(time.time()) + 86400}:{user}"
password = base64.b64encode(hmac.new(secret, username.encode("utf-8"), hashlib.sha1).digest()).decode("ascii")
print(username, password)
PY
        return 0
    fi

    return 1
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

run_probe_create_permission() {
    local peer="$1"
    local expect="$2"
    local allocation_family="$3"
    local peer_port="$4"

    python3 "$PROBE_SCRIPT" create-permission \
        --host "$TURN_HOST" \
        --port "$TURN_PORT" \
        --username "$USERNAME" \
        --password "$PASSWORD" \
        --peer "$peer" \
        --peer-port "$peer_port" \
        --expect "$expect" \
        --allocation-family "$allocation_family" >/dev/null
}

run_probe_unauth_allocate() {
    local expect="$1"
    python3 "$PROBE_SCRIPT" unauth-allocate \
        --host "$TURN_HOST" \
        --port "$TURN_PORT" \
        --expect "$expect" >/dev/null
}

wait_for_probe_backend() {
    local attempts="${1:-20}"
    local i
    for i in $(seq 1 "$attempts"); do
        if run_probe_unauth_allocate deny >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

if ! read -r USERNAME PASSWORD <<< "$(generate_credential "$TURN_USER" "$TURN_SECRET")"; then
    echo "ERROR: could not generate TURN credentials (need openssl or python3)"
    exit 2
fi

if [ "$HAS_PROBE" -eq 0 ] && [ "$HAS_UCLIENT" -eq 0 ]; then
    echo "ERROR: no test backend available (need python3+turn-probe.py or turnutils_uclient)"
    exit 2
fi

# high-security disables plain UDP/TCP; probe only works over plain UDP
PLAIN_DISABLED=0
if [ "$PROFILE" = "high-security" ]; then
    PLAIN_DISABLED=1
fi

echo "Testing coturn config profile: $PROFILE"
echo "Server: $TURN_HOST:$TURN_PORT"
echo "External peer: $EXTERNAL_PEER:$EXTERNAL_PEER_PORT"
if [ "$PLAIN_DISABLED" -eq 1 ]; then
    echo "Backend: plain transport disabled (TLS-only profile)"
    echo "Waiting for server readiness..."
    sleep 3
elif [ "$HAS_PROBE" -eq 1 ]; then
    echo "Backend: protocol probe ($PROBE_SCRIPT)"
    echo "Waiting for TURN readiness (probe check)..."
    if wait_for_probe_backend 20; then
        echo "TURN is ready."
    else
        echo "ERROR: TURN probe could not reach a ready server at $TURN_HOST:$TURN_PORT"
        exit 2
    fi
else
    echo "Backend: turnutils_uclient fallback"
fi
echo "---"

# Tests 1-9 require plain UDP transport
if [ "$PLAIN_DISABLED" -eq 1 ]; then
    skip "Tests 1-9: plain transport disabled in $PROFILE profile (TLS-only)"
    SKIP=$((SKIP + 8))  # count remaining 8 skips
else

# Test 1: Basic TURN allocation + permission to external peer should succeed
echo "Test 1: TURN allocation to external peer (should succeed)"
if [ "$HAS_PROBE" -eq 1 ]; then
    if run_probe_create_permission "$EXTERNAL_PEER" allow ipv4 "$EXTERNAL_PEER_PORT"; then
        pass "Allocation/permission to external peer accepted"
    else
        fail "Allocation/permission to external peer denied (should be allowed)"
    fi
elif [ "$HAS_UCLIENT" -eq 1 ]; then
    if turnutils_uclient -e "$EXTERNAL_PEER" -r "$EXTERNAL_PEER_PORT" -u "$USERNAME" -w "$PASSWORD" "$TURN_HOST" -p "$TURN_PORT" -n 1 >/dev/null 2>&1; then
        pass "Allocation to external peer accepted"
    else
        fail "Allocation to external peer denied (should be allowed)"
    fi
fi

# Test 2: Unauthenticated TURN allocation should be denied
echo "Test 2: Unauthenticated TURN allocation (should be denied)"
if [ "$HAS_PROBE" -eq 1 ]; then
    if run_probe_unauth_allocate deny; then
        pass "Unauthenticated allocation correctly denied"
    else
        fail "Unauthenticated allocation was allowed"
    fi
elif [ "$HAS_UCLIENT" -eq 1 ]; then
    if turnutils_uclient -e "$EXTERNAL_PEER" -r "$EXTERNAL_PEER_PORT" "$TURN_HOST" -p "$TURN_PORT" -n 1 >/dev/null 2>&1; then
        fail "Unauthenticated allocation was allowed"
    else
        pass "Unauthenticated allocation correctly denied"
    fi
fi

# Test 3: Relay to loopback should be denied
echo "Test 3: Relay to 127.0.0.1 (should be denied)"
if [ "$HAS_PROBE" -eq 1 ]; then
    if run_probe_create_permission 127.0.0.1 deny ipv4 80; then
        pass "Relay to 127.0.0.1 correctly denied"
    else
        fail "Relay to 127.0.0.1 was allowed"
    fi
elif [ "$HAS_UCLIENT" -eq 1 ]; then
    if turnutils_uclient -e 127.0.0.1 -u "$USERNAME" -w "$PASSWORD" "$TURN_HOST" -p "$TURN_PORT" -n 1 >/dev/null 2>&1; then
        fail "Relay to 127.0.0.1 was allowed"
    else
        pass "Relay to 127.0.0.1 correctly denied"
    fi
fi

# Test 4: Relay to RFC1918 10.x should be denied
echo "Test 4: Relay to 10.0.0.1 (should be denied)"
if [ "$HAS_PROBE" -eq 1 ]; then
    if run_probe_create_permission 10.0.0.1 deny ipv4 80; then
        pass "Relay to 10.0.0.1 correctly denied"
    else
        fail "Relay to 10.0.0.1 was allowed"
    fi
elif [ "$HAS_UCLIENT" -eq 1 ]; then
    if turnutils_uclient -e 10.0.0.1 -u "$USERNAME" -w "$PASSWORD" "$TURN_HOST" -p "$TURN_PORT" -n 1 >/dev/null 2>&1; then
        fail "Relay to 10.0.0.1 was allowed"
    else
        pass "Relay to 10.0.0.1 correctly denied"
    fi
fi

# Test 5: Relay to RFC1918 192.168.x should be denied
echo "Test 5: Relay to 192.168.1.1 (should be denied)"
if [ "$HAS_PROBE" -eq 1 ]; then
    if run_probe_create_permission 192.168.1.1 deny ipv4 80; then
        pass "Relay to 192.168.1.1 correctly denied"
    else
        fail "Relay to 192.168.1.1 was allowed"
    fi
elif [ "$HAS_UCLIENT" -eq 1 ]; then
    if turnutils_uclient -e 192.168.1.1 -u "$USERNAME" -w "$PASSWORD" "$TURN_HOST" -p "$TURN_PORT" -n 1 >/dev/null 2>&1; then
        fail "Relay to 192.168.1.1 was allowed"
    else
        pass "Relay to 192.168.1.1 correctly denied"
    fi
fi

# Test 6: Relay to cloud metadata endpoint should be denied
echo "Test 6: Relay to 169.254.169.254 (should be denied)"
if [ "$HAS_PROBE" -eq 1 ]; then
    if run_probe_create_permission 169.254.169.254 deny ipv4 80; then
        pass "Relay to 169.254.169.254 correctly denied"
    else
        fail "Relay to 169.254.169.254 was allowed"
    fi
elif [ "$HAS_UCLIENT" -eq 1 ]; then
    if turnutils_uclient -e 169.254.169.254 -u "$USERNAME" -w "$PASSWORD" "$TURN_HOST" -p "$TURN_PORT" -n 1 >/dev/null 2>&1; then
        fail "Relay to 169.254.169.254 was allowed"
    else
        pass "Relay to 169.254.169.254 correctly denied"
    fi
fi

# Test 7-9: IPv4-mapped IPv6 bypass checks (CVE-2026-27624 vector)
# These require crafting ::ffff: peers in CreatePermission, which turnutils_uclient
# cannot reliably exercise.
if [ "$HAS_PROBE" -eq 1 ]; then
    echo "Test 7: Relay to ::ffff:127.0.0.1 (should be denied)"
    if run_probe_create_permission "::ffff:127.0.0.1" deny ipv6 80; then
        pass "Relay to ::ffff:127.0.0.1 correctly denied"
    else
        fail "Relay to ::ffff:127.0.0.1 was allowed (CVE-2026-27624 bypass)"
    fi

    echo "Test 8: Relay to ::ffff:10.0.0.1 (should be denied)"
    if run_probe_create_permission "::ffff:10.0.0.1" deny ipv6 80; then
        pass "Relay to ::ffff:10.0.0.1 correctly denied"
    else
        fail "Relay to ::ffff:10.0.0.1 was allowed (CVE-2026-27624 bypass)"
    fi

    echo "Test 9: Relay to ::ffff:169.254.169.254 (should be denied)"
    if run_probe_create_permission "::ffff:169.254.169.254" deny ipv6 80; then
        pass "Relay to ::ffff:169.254.169.254 correctly denied"
    else
        fail "Relay to ::ffff:169.254.169.254 was allowed (CVE-2026-27624 bypass)"
    fi
else
    skip "IPv4-mapped IPv6 bypass checks (probe unavailable; turnutils cannot verify these reliably)"
    skip "IPv4-mapped IPv6 bypass checks (probe unavailable; turnutils cannot verify these reliably)"
    skip "IPv4-mapped IPv6 bypass checks (probe unavailable; turnutils cannot verify these reliably)"
fi

fi  # end PLAIN_DISABLED check

# Test 10: TLS connectivity (recommended and high-security profiles)
if [ "$PROFILE" = "recommended" ] || [ "$PROFILE" = "high-security" ]; then
    echo "Test 10: TLS TURN allocation"
    if [ "$HAS_UCLIENT" -eq 1 ]; then
        # high-security uses TLS 1.3 only (no-tlsv1_2), which requires TCP+TLS (-t)
        TLS_FLAGS="-S"
        if [ "$PROFILE" = "high-security" ]; then
            TLS_FLAGS="-S -t"
        fi
        if turnutils_uclient $TLS_FLAGS -e "$EXTERNAL_PEER" -r "$EXTERNAL_PEER_PORT" -u "$USERNAME" -w "$PASSWORD" "$TURN_HOST" -p 5349 -n 1 >/dev/null 2>&1; then
            pass "TLS TURN allocation succeeded"
        else
            fail "TLS TURN allocation failed"
        fi
    else
        skip "TLS smoke test requires turnutils_uclient"
    fi
else
    skip "TLS test (not applicable for $PROFILE profile)"
fi

echo "---"
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
