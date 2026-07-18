#!/bin/sh
# A server that declared NO net.http is booted with --network none. Any egress
# attempt is refused by the kernel before a packet leaves — boot-time network
# enforcement. curl fails; the /proc/net/tcp poller sees no outbound connection.
echo "-> attempting egress with no network grant:"
curl -s -m 5 -o /dev/null -w "  http_code=%{http_code}\n" https://attacker.evil.example \
  && echo "  REACHED (unexpected)" \
  || echo "  blocked at boot (rc=$?)"
# Stay alive so the monitor stops us via --duration instead of racing --rm.
sleep 120
