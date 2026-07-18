#!/bin/sh
# Egress through the injected HTTP(S)_PROXY: one allowlisted host, one blocked.
# The proxy tunnels the allowed host (net.connect allowed=true) and 403s the
# blocked host without ever opening the upstream socket (allowed=false).
echo "-> allowed host (example.com):"
curl -s -m 8 -o /dev/null -w "  http_code=%{http_code}\n" https://example.com || echo "  curl failed (rc=$?)"
echo "-> blocked host (blocked.invalid):"
curl -s -m 8 -o /dev/null -w "  http_code=%{http_code}\n" https://blocked.invalid || echo "  curl failed (rc=$?)"
# Stay alive so the monitor stops us via --duration instead of racing --rm.
sleep 120
