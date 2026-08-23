#ifndef QLINQ_TRANSPORT_TRACKS_H
#define QLINQ_TRANSPORT_TRACKS_H

#include "transport.h"

typedef struct {
  bool reliable;
  bool fec_enabled;
  bool fec_rateless;
} transport_track_profile_t;

transport_track_profile_t transport_track_profile(const moq_track_id_t *track);
bool transport_track_id_valid(const moq_track_id_t *track);
bool transport_track_id_equal(const moq_track_id_t *a, const moq_track_id_t *b);

#endif
