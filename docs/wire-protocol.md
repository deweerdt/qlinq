# qlinq wire protocol

This document describes qlinq's private peer protocol. All multibyte integers
are unsigned and encoded in network byte order. The current protocol version is
1. A peer must reject an unsupported stream-frame version. Invalid datagrams
are discarded.

Version 1 is the initial versioned layout. It uses 64-bit object identifiers
and preserves object metadata on reliable streams. The legacy unversioned
format is not supported.

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
track-object payload has a 20-byte metadata header followed by application data.

| Type | Name | Payload |
| ---: | --- | --- |
| 1 | Subscribe | Track descriptor |
| 2 | Unsubscribe | Track descriptor |
| 3 | Unicast | Application bytes |
| 4 | Authentication request | Token bytes, at most 65,535 |
| 5 | Authentication response | One status byte: `0` or `1` |
| 6 | Keyframe request | Track descriptor |
| 7 | Reliable track object | Object metadata followed by object bytes |
| 8 | NACK | NACK descriptor |

A track descriptor contains alias, track type, flags, one-byte name length,
and up to 63 name bytes. A NACK descriptor contains alias, a flags byte,
64-bit group ID, 64-bit object ID, a 16-bit missing-symbol count, and that many
16-bit symbol indices. The count is limited to 1,024. Flag `0x01` requests a
whole object and requires a zero symbol count; all other flag bits are reserved.

Reliable-object metadata contains an alias, keyframe flag, priority, one
reserved zero byte, 64-bit group ID, and 64-bit object ID. Each unidirectional
reliable track stream is bound to the alias in its first
object frame. A later frame with a different alias is a protocol error.

## Datagram envelope

Datagrams start with the same magic and version followed by a datagram type.
Type 1 is an FEC symbol and type 2 is telemetry.

The FEC header is 44 bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | Magic bytes `QL` |
| 2 | 1 | Protocol version |
| 3 | 1 | Datagram type (`1`) |
| 4 | 1 | Track alias |
| 5 | 1 | Keyframe flag (`0` or `1`) |
| 6 | 1 | Priority |
| 7 | 1 | Path ID |
| 8 | 8 | Group ID |
| 16 | 8 | Object ID |
| 24 | 2 | Symbol index |
| 26 | 2 | Total symbols |
| 28 | 2 | Data symbols |
| 30 | 2 | Symbol size |
| 32 | 4 | Original object size |
| 36 | 8 | Send timestamp in nanoseconds |
| 44 | variable | Exactly one symbol |

The telemetry datagram is exactly 24 bytes: the four-byte envelope, path ID,
three reserved zero bytes, an eight-byte send timestamp, and an eight-byte
receive timestamp.

Connection closes use stable application error codes: `0x100` for malformed or
unsupported protocol input, `0x101` for authentication failures, and `0x102`
for peer-triggered resource-limit violations.

## Evolution rules

- Change the version for incompatible layouts or semantics.
- Add a new type for compatible new messages; older peers will reject
  unknown stream types and discard unknown datagram types.
- Reserved fields must be sent as zero and validated on receipt.
- Never serialize C structs directly. Use the bounded codec in
  `src/common/transport_wire.c` so padding, alignment, and host byte order do
  not affect the wire representation.
