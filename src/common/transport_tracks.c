#include "transport_tracks.h"

#include "transport_protocol.h"

#include <string.h>

transport_track_profile_t transport_track_profile(const moq_track_id_t *track) {
  transport_track_profile_t profile = {
      .reliable = (track->flags & MOQ_TRACK_FLAG_RELIABLE) != 0,
      .fec_enabled = (track->flags & MOQ_TRACK_FLAG_FEC_ENABLED) != 0,
      .fec_rateless = (track->flags & MOQ_TRACK_FLAG_FEC_RATELESS) != 0};
  return profile;
}

bool transport_track_id_valid(const moq_track_id_t *track) {
  if (!track ||
      strnlen(track->name, sizeof(track->name)) == sizeof(track->name))
    return false;
  if (!transport_track_type_valid((uint8_t)track->type))
    return false;
  const uint8_t valid_flags = MOQ_TRACK_FLAG_RELIABLE |
                              MOQ_TRACK_FLAG_FEC_ENABLED |
                              MOQ_TRACK_FLAG_FEC_RATELESS;
  return (track->flags & ~valid_flags) == 0;
}

bool transport_track_id_equal(const moq_track_id_t *a,
                              const moq_track_id_t *b) {
  return a && b && a->type == b->type && a->flags == b->flags &&
         strcmp(a->name, b->name) == 0;
}
