#include "transport_wire.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  qlinq_wire_frame_t frame;
  (void)qlinq_wire_decode_frame(data, size, 1024U * 1024U, &frame);

  qlinq_wire_track_t track;
  (void)qlinq_wire_decode_track(data, size, &track);

  qlinq_wire_nack_t nack;
  if (qlinq_wire_decode_nack(data, size, &nack) == QLINQ_WIRE_OK) {
    for (size_t i = 0; i < nack.missing_count; i++) {
      uint16_t index;
      (void)qlinq_wire_nack_index(&nack, i, &index);
    }
  }

  qlinq_wire_track_object_t object;
  const uint8_t *payload;
  size_t payload_len;
  (void)qlinq_wire_decode_track_object(data, size, &object, &payload,
                                       &payload_len);

  qlinq_wire_fec_header_t fec;
  (void)qlinq_wire_decode_fec_header(data, size, &fec);

  qlinq_wire_telemetry_t telemetry;
  (void)qlinq_wire_decode_telemetry(data, size, &telemetry);

  uint8_t datagram_type;
  (void)qlinq_wire_decode_datagram_type(data, size, &datagram_type);
  return 0;
}
