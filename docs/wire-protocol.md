# qlinq wire protocol

This document describes qlinq's private peer protocol. All multibyte integers
are unsigned and encoded in network byte order. The current protocol version is
1. A peer must reject an unsupported stream-frame version. Invalid datagrams
are discarded.

Version 1 is intentionally incompatible with the earlier unversioned format.
Deployments must upgrade both peers together.

## Stream frame envelope

Control messages and reliable track objects use one common envelope:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | Magic bytes `QL` (`0x51 0x4c`) |
| 2 | 1 | Protocol version (`1`) |
| 3 | 1 | Frame type |
| 4 | 4 | Payload length |
| 8 | variable | Frame payload |

The receiver buffers incomplete frames and rejects unknown frame types or
payloads above the configured limit. The maximum reliable object is 1 MiB; a
track-object payload has one additional alias byte.

| Type | Name | Payload |
| ---: | --- | --- |
| 1 | Subscribe | Track descriptor |
| 2 | Unsubscribe | Track descriptor |
| 3 | Unicast | Application bytes |
| 4 | Authentication request | Token bytes, at most 65,535 |
| 5 | Authentication response | One status byte: `0` or `1` |
| 6 | Keyframe request | Track descriptor |
| 7 | Reliable track object | Alias byte followed by object bytes |
| 8 | NACK | NACK descriptor |

A track descriptor contains alias, track type, flags, one-byte name length,
and up to 63 name bytes. A NACK descriptor contains alias, one reserved zero
byte, group ID, object ID, a 16-bit missing-symbol count, and that many 16-bit
symbol indices. The count is limited to 1,024.

Each unidirectional reliable track stream is bound to the alias in its first
object frame. A later frame with a different alias is a protocol error.

## Datagram envelope

Datagrams start with the same magic and version followed by a datagram type.
Type 1 is an FEC symbol and type 2 is telemetry.

The FEC header is 36 bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | Magic bytes `QL` |
| 2 | 1 | Protocol version |
| 3 | 1 | Datagram type (`1`) |
| 4 | 1 | Track alias |
| 5 | 1 | Keyframe flag (`0` or `1`) |
| 6 | 1 | Priority |
| 7 | 1 | Path ID |
| 8 | 4 | Group ID |
| 12 | 4 | Object ID |
| 16 | 2 | Symbol index |
| 18 | 2 | Total symbols |
| 20 | 2 | Data symbols |
| 22 | 2 | Symbol size |
| 24 | 4 | Original object size |
| 28 | 8 | Send timestamp in nanoseconds |
| 36 | variable | Exactly one symbol |

The telemetry datagram is exactly 24 bytes: the four-byte envelope, path ID,
three reserved zero bytes, an eight-byte send timestamp, and an eight-byte
receive timestamp.

## Evolution rules

- Change the version for incompatible layouts or semantics.
- Add a new type for compatible new messages; old version-1 peers will reject
  unknown stream types and discard unknown datagram types.
- Reserved fields must be sent as zero and validated on receipt.
- Never serialize C structs directly. Use the bounded codec in
  `src/common/transport_wire.c` so padding, alignment, and host byte order do
  not affect the wire representation.
