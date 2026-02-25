#!/bin/bash
# Test coturn configuration security
#
# Uses turn-probe.py for all protocol-level checks including TLS.
#
# Usage:
#   docker compose up -d
#   docker compose run --rm test-runner
#
# Test a specific profile:
#   COTURN_PROFILE=high-security docker compose up -d
#   COTURN_PROFILE=high-security docker compose run --rm test-runner

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TURN_HOST="${TURN_HOST:-127.0.0.1}"
TURN_PORT="${TURN_PORT:-3478}"
TURN_TLS_PORT="${TURN_TLS_PORT:-5349}"
TURN_SECRET="${TURN_SECRET:-testing-secret-do-not-use-in-production}"
TURN_USER="${TURN_USER:-test}"
PROFILE="${COTURN_PROFILE:-recommended}"

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
    echo "ERROR: turn-probe.py not found"
    exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required"
    exit 2
fi

# Generate TURN credential (HMAC-based as per RFC 5389 / use-auth-secret)
generate_credential() {
    python3 - "$1" "$2" <<'PY'
import base64, hashlib, hmac, sys, time
user, secret = sys.argv[1], sys.argv[2].encode("utf-8")
username = f"{int(time.time()) + 86400}:{user}"
password = base64.b64encode(hmac.new(secret, username.encode("utf-8"), hashlib.sha1).digest()).decode("ascii")
print(username, password)
PY
}

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  SKIP: $1"; SKIP=$((SKIP + 1)); }

run_probe() {
    python3 "$PROBE_SCRIPT" create-permission \
        --host "$TURN_HOST" --port "$TURN_PORT" \
        --username "$USERNAME" --password "$PASSWORD" \
        --peer "$1" --peer-port "$2" \
        --expect "$3" --allocation-family "$4" \
        $PROBE_FLAGS >/dev/null
}

run_probe_unauth() {
    python3 "$PROBE_SCRIPT" unauth-allocate \
        --host "$TURN_HOST" --port "$TURN_PORT" \
        --expect "$1" $PROBE_FLAGS >/dev/null
}

wait_for_turn() {
    local i
    for i in $(seq 1 20); do
        if run_probe_unauth deny >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    return 1
}

if ! read -r USERNAME PASSWORD <<< "$(generate_credential "$TURN_USER" "$TURN_SECRET")"; then
    echo "ERROR: could not generate TURN credentials"
    exit 2
fi

# high-security disables plain UDP/TCP, must use TLS
PROBE_FLAGS=""
if [ "$PROFILE" = "high-security" ]; then
    TURN_PORT="$TURN_TLS_PORT"
    PROBE_FLAGS="--tls"
fi

echo "Testing coturn config profile: $PROFILE"
echo "Server: $TURN_HOST:$TURN_PORT (TLS: $TURN_TLS_PORT)"
echo "External peer: $EXTERNAL_PEER:$EXTERNAL_PEER_PORT"
echo "Waiting for TURN readiness..."

if wait_for_turn; then
    echo "TURN is ready."
else
    echo "ERROR: could not reach TURN at $TURN_HOST:$TURN_PORT"
    exit 2
fi
echo "---"

# --- Test definitions ---
# Format: peer|port|expect|family|label
TESTS=(
    "$EXTERNAL_PEER|$EXTERNAL_PEER_PORT|allow|ipv4|External peer allocation"
    "127.0.0.1|80|deny|ipv4|Relay to loopback"
    "10.0.0.1|80|deny|ipv4|Relay to RFC1918 10.x"
    "192.168.1.1|80|deny|ipv4|Relay to RFC1918 192.168.x"
    "169.254.169.254|80|deny|ipv4|Relay to cloud metadata"
    "::ffff:127.0.0.1|80|deny|ipv6|IPv4-mapped loopback (CVE-2026-27624)"
    "::ffff:10.0.0.1|80|deny|ipv6|IPv4-mapped RFC1918 (CVE-2026-27624)"
    "::ffff:169.254.169.254|80|deny|ipv6|IPv4-mapped metadata (CVE-2026-27624)"
)

N=0
for test in "${TESTS[@]}"; do
    IFS='|' read -r peer port expect family label <<< "$test"
    N=$((N + 1))
    echo "Test $N: $label (should $expect)"
    if run_probe "$peer" "$port" "$expect" "$family"; then
        pass "$label"
    else
        fail "$label"
    fi
done

# Unauthenticated allocation check
N=$((N + 1))
echo "Test $N: Unauthenticated allocation (should deny)"
if run_probe_unauth deny; then
    pass "Unauthenticated allocation denied"
else
    fail "Unauthenticated allocation was allowed"
fi

# TLS connectivity (recommended and high-security profiles)
N=$((N + 1))
if [ "$PROFILE" = "recommended" ] || [ "$PROFILE" = "high-security" ]; then
    echo "Test $N: TLS TURN allocation"
    if python3 "$PROBE_SCRIPT" create-permission \
        --host "$TURN_HOST" --port "$TURN_TLS_PORT" --tls \
        --username "$USERNAME" --password "$PASSWORD" \
        --peer "$EXTERNAL_PEER" --peer-port "$EXTERNAL_PEER_PORT" \
        --expect allow --allocation-family ipv4 >/dev/null; then
        pass "TLS TURN allocation"
    else
        fail "TLS TURN allocation"
    fi
else
    skip "TLS test (not applicable for $PROFILE)"
fi

echo "---"
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
