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
- **`high-security`** - Maximum restrictions: allowlist-only peer access, TLS 1.3 only, aggressive rate limits. For sensitive deployments.

## Running tests

```bash
# Requires turnutils_uclient (ships with coturn)
# Make sure coturn is running first
./tests/test-config.sh

# Test a specific profile
COTURN_PROFILE=minimal ./tests/test-config.sh
```

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
