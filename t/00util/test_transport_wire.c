#include "transport_wire.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "wire test failed: %s\n", message);                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)

int main(void) {
  uint8_t payload[4096];
  uint8_t frame_buf[8192];
  size_t payload_len = 0;
  size_t frame_len = 0;

  qlinq_wire_track_t track = {
      .alias = 9, .track_type = 4, .flags = 6, .name = "telemetry/input"};
  CHECK(qlinq_wire_encode_track(payload, sizeof(payload), &track,
                                &payload_len) == QLINQ_WIRE_OK,
        "track encode");
  CHECK(qlinq_wire_encode_frame(frame_buf, sizeof(frame_buf),
                                QLINQ_WIRE_SUBSCRIBE, payload, payload_len,
                                sizeof(payload), &frame_len) == QLINQ_WIRE_OK,
        "frame encode");

  qlinq_wire_frame_t frame;
  CHECK(qlinq_wire_decode_frame(frame_buf, QLINQ_WIRE_FRAME_HEADER_SIZE - 1,
                                sizeof(payload),
                                &frame) == QLINQ_WIRE_NEED_MORE,
        "partial header");
  CHECK(qlinq_wire_decode_frame(frame_buf, frame_len - 1, sizeof(payload),
                                &frame) == QLINQ_WIRE_NEED_MORE,
        "partial payload");
  CHECK(qlinq_wire_decode_frame(frame_buf, frame_len, sizeof(payload),
                                &frame) == QLINQ_WIRE_OK,
        "frame decode");
  CHECK(frame.type == QLINQ_WIRE_SUBSCRIBE && frame.consumed == frame_len,
        "frame metadata");

  qlinq_wire_track_t decoded_track;
  CHECK(qlinq_wire_decode_track(frame.payload, frame.payload_len,
                                &decoded_track) == QLINQ_WIRE_OK,
        "track decode");
  CHECK(decoded_track.alias == track.alias &&
            decoded_track.track_type == track.track_type &&
            decoded_track.flags == track.flags &&
            strcmp(decoded_track.name, track.name) == 0,
        "track roundtrip");

  uint8_t corrupted[8192];
  memcpy(corrupted, frame_buf, frame_len);
  corrupted[2] = QLINQ_WIRE_VERSION + 1;
  CHECK(qlinq_wire_decode_frame(corrupted, frame_len, sizeof(payload),
                                &frame) == QLINQ_WIRE_UNSUPPORTED_VERSION,
        "version rejection");
  memcpy(corrupted, frame_buf, frame_len);
  corrupted[0] ^= 0xff;
  CHECK(qlinq_wire_decode_frame(corrupted, frame_len, sizeof(payload),
                                &frame) == QLINQ_WIRE_INVALID,
        "magic rejection");
  memcpy(corrupted, frame_buf, frame_len);
  corrupted[3] = 0xff;
  CHECK(qlinq_wire_decode_frame(corrupted, frame_len, sizeof(payload),
                                &frame) == QLINQ_WIRE_INVALID,
        "unknown type rejection");
  CHECK(qlinq_wire_decode_frame(frame_buf, frame_len, payload_len - 1,
                                &frame) == QLINQ_WIRE_TOO_LARGE,
        "configured size limit");
  CHECK(qlinq_wire_encode_frame_header(frame_buf, QLINQ_WIRE_FRAME_HEADER_SIZE,
                                       QLINQ_WIRE_TRACK_OBJECT, 17,
                                       16) == QLINQ_WIRE_TOO_LARGE,
        "frame header size limit");

  uint8_t malformed_track[] = {9, 4, 0, 2, 'x'};
  CHECK(qlinq_wire_decode_track(malformed_track, sizeof(malformed_track),
                                &decoded_track) == QLINQ_WIRE_INVALID,
        "track length mismatch");

  const uint16_t missing[] = {1, 7, 1023};
  CHECK(qlinq_wire_encode_nack(payload, sizeof(payload), 13, 42, 99, missing, 3,
                               &payload_len) == QLINQ_WIRE_OK,
        "nack encode");
  qlinq_wire_nack_t nack;
  CHECK(qlinq_wire_decode_nack(payload, payload_len, &nack) == QLINQ_WIRE_OK,
        "nack decode");
  CHECK(nack.alias == 13 && nack.group_id == 42 && nack.object_id == 99 &&
            nack.missing_count == 3,
        "nack metadata");
  for (size_t i = 0; i < 3; i++) {
    uint16_t index = 0;
    CHECK(qlinq_wire_nack_index(&nack, i, &index) && index == missing[i],
          "nack index roundtrip");
  }
  payload[1] = 1;
  CHECK(qlinq_wire_decode_nack(payload, payload_len, &nack) ==
            QLINQ_WIRE_INVALID,
        "nack reserved byte");
  payload[1] = 0;
  payload[11] = 4;
  CHECK(qlinq_wire_decode_nack(payload, payload_len, &nack) ==
            QLINQ_WIRE_INVALID,
        "nack count mismatch");

  qlinq_wire_fec_header_t fec = {.alias = 12,
                                 .is_keyframe = true,
                                 .priority = 2,
                                 .path_id = 3,
                                 .group_id = 123,
                                 .object_id = 456,
                                 .symbol_index = 7,
                                 .total_symbols = 20,
                                 .data_symbols = 16,
                                 .symbol_size = 1200,
                                 .original_size = 19000,
                                 .send_time_ns = UINT64_C(1234567890123)};
  CHECK(qlinq_wire_encode_fec_header(payload, sizeof(payload), &fec) ==
            QLINQ_WIRE_OK,
        "FEC encode");
  qlinq_wire_fec_header_t decoded_fec;
  CHECK(qlinq_wire_decode_fec_header(payload, QLINQ_WIRE_FEC_HEADER_SIZE,
                                     &decoded_fec) == QLINQ_WIRE_OK,
        "FEC decode");
  uint8_t datagram_type = 0;
  CHECK(qlinq_wire_decode_datagram_type(payload, QLINQ_WIRE_FEC_HEADER_SIZE,
                                        &datagram_type) == QLINQ_WIRE_OK &&
            datagram_type == QLINQ_WIRE_DATAGRAM_FEC,
        "FEC datagram type");
  CHECK(decoded_fec.alias == fec.alias &&
            decoded_fec.is_keyframe == fec.is_keyframe &&
            decoded_fec.priority == fec.priority &&
            decoded_fec.path_id == fec.path_id &&
            decoded_fec.group_id == fec.group_id &&
            decoded_fec.object_id == fec.object_id &&
            decoded_fec.symbol_index == fec.symbol_index &&
            decoded_fec.total_symbols == fec.total_symbols &&
            decoded_fec.data_symbols == fec.data_symbols &&
            decoded_fec.symbol_size == fec.symbol_size &&
            decoded_fec.original_size == fec.original_size &&
            decoded_fec.send_time_ns == fec.send_time_ns,
        "FEC roundtrip");
  payload[5] = 2;
  CHECK(qlinq_wire_decode_fec_header(payload, QLINQ_WIRE_FEC_HEADER_SIZE,
                                     &decoded_fec) == QLINQ_WIRE_INVALID,
        "FEC keyframe validation");

  qlinq_wire_telemetry_t telemetry = {.path_id = 2,
                                      .send_time_ns = UINT64_C(987654321),
                                      .recv_time_ns = UINT64_C(987655555)};
  CHECK(qlinq_wire_encode_telemetry(payload, sizeof(payload), &telemetry) ==
            QLINQ_WIRE_OK,
        "telemetry encode");
  qlinq_wire_telemetry_t decoded_telemetry;
  CHECK(qlinq_wire_decode_telemetry(payload, QLINQ_WIRE_TELEMETRY_SIZE,
                                    &decoded_telemetry) == QLINQ_WIRE_OK,
        "telemetry decode");
  CHECK(qlinq_wire_decode_datagram_type(payload, QLINQ_WIRE_TELEMETRY_SIZE,
                                        &datagram_type) == QLINQ_WIRE_OK &&
            datagram_type == QLINQ_WIRE_DATAGRAM_TELEMETRY,
        "telemetry datagram type");
  CHECK(decoded_telemetry.path_id == telemetry.path_id &&
            decoded_telemetry.send_time_ns == telemetry.send_time_ns &&
            decoded_telemetry.recv_time_ns == telemetry.recv_time_ns,
        "telemetry roundtrip");
  CHECK(qlinq_wire_decode_telemetry(payload, QLINQ_WIRE_TELEMETRY_SIZE + 1,
                                    &decoded_telemetry) == QLINQ_WIRE_INVALID,
        "telemetry trailing bytes");
  payload[3] = 0xff;
  CHECK(qlinq_wire_decode_datagram_type(payload, QLINQ_WIRE_TELEMETRY_SIZE,
                                        &datagram_type) == QLINQ_WIRE_INVALID,
        "unknown datagram type");
  CHECK(qlinq_wire_decode_datagram_type(payload, 3, &datagram_type) ==
            QLINQ_WIRE_NEED_MORE,
        "partial datagram envelope");

  printf("===TRANSPORT WIRE OK===\n");
  return 0;
}
