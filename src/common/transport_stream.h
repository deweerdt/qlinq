#ifndef QLINQ_TRANSPORT_STREAM_H
#define QLINQ_TRANSPORT_STREAM_H

#include "transport.h"
#include "transport_wire.h"

#include "quicly.h"

#define TRANSPORT_WIRE_MAX_STREAM_PAYLOAD                                      \
  (TRANSPORT_MAX_RELIABLE_OBJECT_SIZE + QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE)

bool transport_stream_write_parts(quicly_stream_t *stream, uint8_t type,
                                  const void *prefix, size_t prefix_len,
                                  const void *payload, size_t payload_len);
bool transport_stream_write_frame(quicly_stream_t *stream, uint8_t type,
                                  const void *payload, size_t payload_len);
bool transport_stream_write_track_frame(quicly_stream_t *stream, uint8_t type,
                                        uint8_t alias,
                                        const moq_track_id_t *track_id);
bool transport_stream_write_object_frame(quicly_stream_t *stream, uint8_t alias,
                                         const moq_object_t *object);
bool transport_stream_write_track_end_frame(quicly_stream_t *stream,
                                            uint8_t alias, uint64_t group_id,
                                            uint64_t final_object_id);
bool transport_stream_write_track_checkpoint_frame(
    quicly_stream_t *stream, uint8_t alias, uint64_t group_id,
    uint64_t first_object_id, uint64_t final_object_id, bool baseline);
bool transport_stream_write_track_checkpoint_ack_frame(
    quicly_stream_t *stream, uint8_t alias, uint64_t group_id,
    uint64_t final_object_id);

#endif
