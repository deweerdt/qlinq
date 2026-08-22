# qlinq

[![CI](https://github.com/sleepybishop/qlinq/actions/workflows/ci.yml/badge.svg)](https://github.com/sleepybishop/qlinq/actions/workflows/ci.yml)

`qlinq` ("clink") is a QUIC-based swiss army knife for different types of data streams. It combines a high-performance network link path manager with forward error correction and provides interfaces via tun devices or unix sockets.

## Features

- **QUIC-native Tunneling**: Low-latency, connection-migrating packet tunnels.
- **Multipath Link Aggregation**: Dynamic path discovery, performance scheduling, and failover across multiple interfaces (Wi-Fi, Ethernet, Satcom, Cellular).
- **Forward Error Correction**: Recover lost packets on high-loss links without retransmission latency.
- **mTLS Authentication**: Full mutual TLS authentication support using custom or system trusted root authorities.

## Building

To compile all targets, run:

```bash
git submodule update --init --recursive
make
```

This produces two main binaries:
- `qlinqd`: The background peer-to-peer network daemon.
- `qlinq-tund`: The lightweight virtual TUN/TAP interface controller.

## Security

`qlinqd` requires an application authentication token and verifies peer
certificates by default. Supply the token through `QLINQ_AUTH_TOKEN` or
`--auth-token`, and use `--ca` when peers are signed by a private CA. For local
testing only, certificate verification can be disabled explicitly with
`--insecure-no-verify`.

```bash
QLINQ_AUTH_TOKEN='replace-with-a-secret' \
  ./qlinqd --listen 8888 --cert peer.crt --key peer.key --ca mesh-ca.crt
```

## Testing

To run the test suite:

```bash
make check
```
