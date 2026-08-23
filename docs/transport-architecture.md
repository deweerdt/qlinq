# Transport architecture

The public transport API remains in `transport.h`. The Quicly implementation is
split into small internal modules with one-way dependencies toward shared data
types and the wire codec.

| Module | Responsibility |
| --- | --- |
| `transport_quicly.c` | Connection lifecycle, event loop, protocol dispatch, publishing orchestration |
| `transport_wire.c` | Versioned, bounded byte-level encoding and decoding |
| `transport_stream.c` | Atomic stream-frame construction and emission |
| `transport_subscriptions.c` | Track/alias lookup, allocation, and stream binding |
| `transport_memory.c` | Packet arena and FEC assembler allocation ownership |
| `transport_fec_state.c` | Reusable FEC contexts and sent-object repair cache |
| `transport_paths.c` | QUIC-path mapping and physical-path selection |
| `transport_repair.c` | Bounded NACK symbol reconstruction |
| `transport_scheduler.c` | Per-connection path and redundancy planning |
| `transport_tls.c` | Certificate loading and verifier initialization |
| `transport_udp.c` | Portable UDP batch emission and Linux GSO acceleration |

The extracted modules do not call the public transport API and do not own the
event loop. `transport_quicly.c` coordinates them, while each module owns the
allocation and invariants of its state. This keeps QUIC callbacks centralized
without exposing private transport structures in the public header.

## Ownership rules

- `transport_memory` initializes and destroys arenas and frame assemblers.
- `transport_subscriptions` is the only code that allocates aliases or changes
  subscription entries.
- `transport_fec_state` owns cached FEC instances and copies of sent objects.
- `transport_stream` emits complete frames in one Quicly egress operation.
- `transport_wire` is the only code that reads or writes multibyte wire fields.
- Path measurements and scheduler state belong to a connection; one client's
  RTT, loss, or telemetry must never determine another client's schedule.
- Incoming FEC assemblers share a 64 MiB transport-wide memory budget and each
  connection has eight active assembler slots.
- NACK handling sends at most 64 requested symbols per repair and accepts at
  most 16 repair requests per connection per second.
- Event payload pointers are borrowed and valid only during the callback.

`transport_publish_ex` distinguishes delivery, buffering, no recipients,
partial delivery, backpressure, invalid input, and internal failure. The legacy
boolean wrapper returns false for partial delivery and all failures.

Component-level tests cover these ownership and lookup boundaries. End-to-end
tests cover connection establishment, authentication, reliable streams,
datagrams, FEC/NACK recovery, and multipath behavior.
