# UDP over QUIC

This branch implements SOCKS5 UDP ASSOCIATE through a single HTTP/3 CONNECT-UDP
proxy using RFC 9221 QUIC DATAGRAM frames. Enable it explicitly:

```json
{
  "listen": "socks://127.0.0.1:1080",
  "proxy": "quic://user:password@proxy.example:443",
  "masque-udp": true
}
```

Pair it with `kinmeic/forwardproxy` branch `codex/udp-over-quic`. The server must
be built with its `scripts/build-udp-caddy.sh`, which applies all three Caddy
patches, and configure `basic_auth` plus `udp`. Existing TCP requests share the
proxy's QUIC connection and retain their independent Naive padding negotiation.
UDP carries an unmodified payload with Context ID zero; it does not use the
TCP padding framer or HTTP DATA as a reliable fallback.

This does not establish browser-equivalent traffic or lower firewall detection
risk than ordinary HTTPS. See the [audit and traffic-risk assessment](udp-over-quic-audit.zh-CN.md).

The application must support SOCKS5 UDP ASSOCIATE, use the returned relay
endpoint and keep the TCP control connection open. IPv4, IPv6, domain targets and
empty UDP payloads are supported. Only one client UDP source endpoint is accepted
per association. FRAG != 0 and invalid packets are discarded.

## Limits and lifetime

`USAGE.txt` documents the `udp-max-*` queue/flow limits, `connect-udp-timeout`
(default 120 seconds), and `socks-udp-association-timeout` (300 seconds). The
listener caps active plus pending associations at 256 and admits new UDP
flows only while its total outbound connection count is below 1024. Each destination owns one
HTTP request stream, while the existing Chromium pool shares QUIC sessions.
Association close destroys every flow. Stream FIN/RESET and QUIC loss complete
pending UDP reads with an error, distinct from a valid zero-byte datagram. A
subsequent client packet can establish a new flow; old data is not replayed.

The client waits for handshake confirmation, peer SETTINGS and successful
CONNECT-UDP authentication before sending UDP. An HTTPS/H2 proxy, direct route
or multi-hop chain cannot silently substitute another transport. The server's
own ACL, resource quotas and rate limits also apply.

A datagram must fit the peer's transport limit and the current outer packet
budget after framing. Too-large datagrams are dropped without resetting an
otherwise healthy flow. A 1200-byte inner QUIC Initial requires an outer path
with additional capacity. Fragmentation, reliable fallback and UDP padding are
not implemented. Domains are resolved remotely; domain-target SOCKS replies use
the original domain address rather than claiming to report the resolved IP.

The standard URI template is
`/.well-known/masque/udp/{target_host}/{target_port}/`. Other client templates
require a compatible server. The paired server deliberately accepts this one
template only.

## Private certificate authorities

`trusted-cert` optionally names a PEM CA bundle added only to this process's
trust anchors. Names, signatures, dates and anchor constraints remain verified;
it neither disables certificate verification nor changes the system trust store.
Invalid/unreadable bundles cause startup failure. It is useful with a private CA
and for the integration runner's temporary localhost certificate.

## Validation

```
ninja -C src/out/Release naive
python3 tests/udp.py --naive src/out/Release/naive --caddy /path/to/patched/caddy
python3 tests/basic.py --naive src/out/Release/naive --server_protocol=http
```

The UDP runner starts local Caddy and echo services with temporary credentials
and a temporary CA. It exercises real SOCKS negotiation, empty/IPv4/IPv6/domain
packets, 1200-byte payloads, malformed fragments, oversized-packet recovery,
source-port pinning and independent associations. `.github/workflows/udp.yml`
runs the paired build and integration on Linux. The manual echo/DNS tools under
`tools/` are additional diagnostics, not substitutes for this regression test.

## Attribution

The SOCKS packet codec, association/generation/queue model and CONNECT-UDP
parameter plumbing are adapted from ZihaoFU245/naiveproxy commit
`ad8a8741573974ec5be25877c5e935f424851bad` under its BSD-style license. This
branch replaces that fork's stream-Capsule transport with QUIC DATAGRAM and adds
capability/handshake gating, close notification, bounded datagram reads, MTU
error handling and paired-server regression tests.
