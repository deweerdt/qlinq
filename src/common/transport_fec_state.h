#ifndef QLINQ_TRANSPORT_FEC_STATE_H
#define QLINQ_TRANSPORT_FEC_STATE_H

#include "fec.h"
#include "transport.h"

#include <stddef.h>
#include <stdint.h>

#define TRANSPORT_SENT_CACHE_SIZE 256U
#define TRANSPORT_FEC_CACHE_SIZE 8U

typedef struct {
  moq_track_id_t track_id;
  uint32_t group_id;
  uint32_t object_id;
  uint8_t *data;
  size_t size;
  uint8_t priority;
  bool is_keyframe;
  uint16_t total_symbols;
  uint16_t data_symbols;
  uint16_t symbol_size;
} sent_object_cache_t;

typedef struct {
  sent_object_cache_t entries[TRANSPORT_SENT_CACHE_SIZE];
  size_t next_entry;
} transport_sent_cache_t;

sent_object_cache_t *transport_sent_cache_find(transport_sent_cache_t *cache,
                                               const moq_track_id_t *track,
                                               uint32_t group_id,
                                               uint32_t object_id);
void transport_sent_cache_store(transport_sent_cache_t *cache,
                                const moq_object_t *object,
                                uint16_t total_symbols, uint16_t data_symbols,
                                uint16_t symbol_size);
void transport_sent_cache_destroy(transport_sent_cache_t *cache);

typedef struct {
  fec_type_t type;
  size_t data_symbols;
  size_t parity_symbols;
  size_t symbol_size;
  fec_t *fec;
  uint64_t last_used_ns;
} transport_fec_cache_entry_t;

typedef struct {
  transport_fec_cache_entry_t entries[TRANSPORT_FEC_CACHE_SIZE];
} transport_fec_cache_t;

fec_t *transport_fec_cache_get(transport_fec_cache_t *cache, fec_type_t type,
                               size_t data_symbols, size_t parity_symbols,
                               size_t symbol_size);
void transport_fec_cache_destroy(transport_fec_cache_t *cache);

#endif
