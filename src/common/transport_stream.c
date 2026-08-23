#include "transport_stream.h"

#include "transport_wire.h"

#include "quicly/streambuf.h"

#include <stdlib.h>
#include <string.h>

bool transport_stream_write_parts(quicly_stream_t *stream, uint8_t type,
                                  const void *prefix, size_t prefix_len,
                                  const void *payload, size_t payload_len) {
  if (!stream || prefix_len > SIZE_MAX - payload_len ||
      (prefix_len > 0 && !prefix) || (payload_len > 0 && !payload))
    return false;
  size_t wire_payload_len = prefix_len + payload_len;
  if (wire_payload_len > TRANSPORT_WIRE_MAX_STREAM_PAYLOAD ||
      wire_payload_len > SIZE_MAX - QLINQ_WIRE_FRAME_HEADER_SIZE)
    return false;

  size_t frame_len = QLINQ_WIRE_FRAME_HEADER_SIZE + wire_payload_len;
  uint8_t stack_buf[256];
  uint8_t *frame =
      frame_len <= sizeof(stack_buf) ? stack_buf : malloc(frame_len);
  if (!frame)
    return false;
  if (qlinq_wire_encode_frame_header(frame, frame_len, type, wire_payload_len,
                                     TRANSPORT_WIRE_MAX_STREAM_PAYLOAD) !=
      QLINQ_WIRE_OK) {
    if (frame != stack_buf)
      free(frame);
    return false;
  }
  if (prefix_len > 0)
    memcpy(frame + QLINQ_WIRE_FRAME_HEADER_SIZE, prefix, prefix_len);
  if (payload_len > 0)
    memcpy(frame + QLINQ_WIRE_FRAME_HEADER_SIZE + prefix_len, payload,
           payload_len);

  int ret = quicly_streambuf_egress_write(stream, frame, frame_len);
  if (frame != stack_buf)
    free(frame);
  return ret == 0;
}

bool transport_stream_write_frame(quicly_stream_t *stream, uint8_t type,
                                  const void *payload, size_t payload_len) {
  return transport_stream_write_parts(stream, type, payload, payload_len, NULL,
                                      0);
}

bool transport_stream_write_track_frame(quicly_stream_t *stream, uint8_t type,
                                        uint8_t alias,
                                        const moq_track_id_t *track_id) {
  if (!track_id)
    return false;
  size_t name_len = strnlen(track_id->name, sizeof(track_id->name));
  if (name_len > QLINQ_WIRE_MAX_TRACK_NAME)
    return false;

  qlinq_wire_track_t wire_track = {.alias = alias,
                                   .track_type = (uint8_t)track_id->type,
                                   .flags = track_id->flags};
  memcpy(wire_track.name, track_id->name, name_len);
  wire_track.name[name_len] = '\0';
  uint8_t payload[4 + QLINQ_WIRE_MAX_TRACK_NAME];
  size_t encoded_len = 0;
  if (qlinq_wire_encode_track(payload, sizeof(payload), &wire_track,
                              &encoded_len) != QLINQ_WIRE_OK)
    return false;
  return transport_stream_write_frame(stream, type, payload, encoded_len);
}

bool transport_stream_write_object_frame(quicly_stream_t *stream, uint8_t alias,
                                         const moq_object_t *object) {
  if (!stream || !object || (object->size > 0 && !object->data) ||
      object->size > TRANSPORT_MAX_RELIABLE_OBJECT_SIZE)
    return false;
  uint8_t header[QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE];
  qlinq_wire_track_object_t wire_object = {.alias = alias,
                                           .is_keyframe = object->is_keyframe,
                                           .priority = object->priority,
                                           .group_id = object->group_id,
                                           .object_id = object->object_id};
  if (qlinq_wire_encode_track_object(header, sizeof(header), &wire_object) !=
      QLINQ_WIRE_OK)
    return false;
  return transport_stream_write_parts(stream, QLINQ_WIRE_TRACK_OBJECT, header,
                                      sizeof(header), object->data,
                                      object->size);
}
