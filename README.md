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
COTURN_PROFILE=insecure docker compose up -d  # negative test profile
```

## Configuration profiles

- **`minimal`** - Bare minimum for production: authentication, basic denied-peer-ip rules, rate limiting.
- **`recommended`** - Full production config: TLS, comprehensive IANA special-purpose IP blocking, protocol hardening, monitoring. This is the default.
- **`high-security`** - Maximum restrictions: allowlist-only peer access, TLS 1.3 only, tighter rate limits. For sensitive deployments.
- **`insecure`** - Intentionally unsafe config for negative testing only. Expected to fail security checks.

## Running tests

Uses a dedicated `test-runner` container (`python:3-alpine`) with the protocol-level probe (`tests/turn-probe.py`) for all checks including TLS.

```bash
# Start coturn, then run tests
docker compose up -d
docker compose run --rm test-runner

# Test a specific profile
COTURN_PROFILE=minimal docker compose up -d
COTURN_PROFILE=minimal docker compose run --rm test-runner

# Negative test: this should FAIL security checks
COTURN_PROFILE=insecure docker compose up -d
COTURN_PROFILE=insecure docker compose run --rm test-runner
```

### What the tests cover

- TURN allocation and CreatePermission to an external peer (should succeed)
- Unauthenticated TURN allocation (should be denied)
- Relay to loopback, RFC1918, and cloud metadata addresses (should be denied)
- IPv4-mapped IPv6 bypass attempts, e.g. `::ffff:127.0.0.1` (CVE-2026-27624 vector, should be denied)
- TLS connectivity (recommended and high-security profiles)

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
