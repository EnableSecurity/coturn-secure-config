# coturn-secure-config

Secure configuration templates for coturn TURN server, with a Docker testing environment. Companion to the [Enable Security coturn security configuration guide](https://www.enablesecurity.com/blog/coturn-security-configuration-guide/).

## Quick start

```bash
# Generate test certificates
./certs/generate-certs.sh

# Start coturn with the recommended config (default)
docker compose up -d

# Or choose a specific profile
COTURN_PROFILE=minimal docker compose up -d
COTURN_PROFILE=high-security docker compose up -d
```

## Configuration profiles

- **`minimal`** - Bare minimum for production: authentication, basic denied-peer-ip rules, rate limiting.
- **`recommended`** - Full production config: TLS, comprehensive IANA special-purpose IP blocking, protocol hardening, monitoring. This is the default.
- **`high-security`** - Maximum restrictions: allowlist-only peer access, TLS 1.3 only, tighter rate limits. For sensitive deployments.

## Running tests

Recommended path (from host): uses the protocol-level probe (`tests/turn-probe.py`) for deterministic ACL/CVE checks.

```bash
# Start coturn, then run tests from host
docker compose up -d
bash tests/test-config.sh

# Test a specific profile
COTURN_PROFILE=minimal docker compose up -d
COTURN_PROFILE=minimal bash tests/test-config.sh
```

Optional fallback (inside coturn container): uses `turnutils_uclient` for smoke checks.

```bash
docker compose exec coturn /opt/tests/test-config.sh
```

### What the tests cover

- TURN allocation/permission to an external peer (should succeed)
- Unauthenticated TURN allocation (should be denied)
- Relay to loopback, RFC1918, and cloud metadata addresses (should be denied)
- IPv4-mapped IPv6 bypass attempts, e.g. `::ffff:127.0.0.1` (CVE-2026-27624 vector, should be denied)
- TLS connectivity smoke test (recommended and high-security profiles, when `turnutils_uclient` is available)

`tests/test-config.sh` auto-selects backend:
- Probe mode (`python3` + `tests/turn-probe.py`) for reliable ACL/CVE verification
- `turnutils_uclient` fallback when probe prerequisites are unavailable

## Production adaptation

Before deploying to production, make the following changes:

- Replace `testing-secret-do-not-use-in-production` with a strong random secret
- Set `external-ip` to your server's public IP
- Use proper TLS certificates (not self-signed)
- Adjust `min-port`/`max-port` relay range as needed
- For the high-security profile: replace example `allowed-peer-ip` values with your actual media server IPs

## Further reading

See the full coturn security configuration guide at Enable Security:

<https://www.enablesecurity.com/blog/coturn-security-configuration-guide/>

## License

Configuration templates are provided under the MIT License.
