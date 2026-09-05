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
payloads above the configured limit. The reliable-object implementation ceiling
is approximately 1 MiB and may be configured lower; a track-object payload has
a 20-byte metadata header followed by application data.

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
| 9 | HELLO | Capability and resource-limit advertisement |
| 10 | Reserved | Experimental Flexicast branch; rejected here |
| 11 | Track completion | Alias, group ID, and final FEC object ID |
| 12 | Recovery checkpoint | Alias, group ID, first and final FEC object IDs |
| 13 | Recovery checkpoint ACK | Alias, group ID, and final FEC object ID |
| 14–255 | Reserved | Rejected by this version |

`HELLO` is the first frame on the bidirectional control stream in each
direction. Application control frames and the public connected event are gated
until both peers have exchanged valid HELLO frames. This is still protocol
version 1: the handshake was added before version 1 had external users.

The HELLO payload is 20 bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 1 | Role: client `0`, server `1` |
| 1 | 1 | Reserved zero byte |
| 2 | 2 | Maximum paths |
| 4 | 4 | Capability flags |
| 8 | 4 | Maximum reliable-object bytes |
| 12 | 4 | Maximum FEC-object bytes |
| 16 | 2 | Maximum subscriptions |
| 18 | 2 | Maximum UDP payload bytes |

Defined capabilities are reliable objects (`0x01`), datagrams (`0x02`),
Reed-Solomon FEC (`0x04`), rateless FEC (`0x08`), multipath (`0x10`),
application authentication (`0x20`), rolling recovery checkpoints (`0x80`),
and degree-of-freedom rateless repair (`0x100`). Unknown capability bits,
duplicate HELLO frames, a peer with the
wrong role, or an application frame before HELLO are protocol errors. Each
connection uses the lower local/peer object, subscription, and UDP-payload
limits.

A track descriptor contains alias, track type, flags, one-byte name length,
and up to 63 name bytes. A NACK descriptor contains alias, a flags byte,
64-bit group ID, 64-bit object ID, and a 16-bit count. The count is limited to
1,024. Flag `0x01` requests a whole object. Flag `0x02` selects rateless repair
and is valid only when the peer advertised `0x100` and the track uses rateless
FEC.

In indexed mode, the count is followed by that many 16-bit missing ESIs. A
whole-object request has a zero count. In rateless mode, the 20-byte descriptor
has no ESI list: the count is the number of additional degrees of freedom. A
rateless whole-object request has a zero count because the source derives the
initial deficit from the cached object's source-symbol count. Peers without
the rateless-repair capability continue using indexed NACKs.

The source emits fresh monotonic RaptorQ ESIs and commits only those admitted
to its bounded datagram queue. Once the 1,024-symbol ESI namespace is
exhausted, it cycles retained systematic symbols so recovery remains possible
without unbounded sender state. Per-peer and source-wide token buckets bound
repair request load.

Checkpoint-capable rateless publishers send a reliable 28-byte recovery
checkpoint after every 32 internal FEC objects. The receiver retains at most
eight outstanding windows and requests absent objects one at a time every 500
milliseconds. Once every object in a window is delivered, it returns a
reliable 17-byte cumulative checkpoint ACK.

`transport_finish_track` flushes grouped data and sends a 17-byte track
completion marker. For checkpoint-capable peers it is the final checkpoint and
uses the same ACK. The source protects cached objects from eviction until every
subscribed capable peer has acknowledged them; a full 256-object protected
cache applies publication backpressure instead of discarding repair state.

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
