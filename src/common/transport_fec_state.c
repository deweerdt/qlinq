#include "transport_fec_state.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t get_time_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static bool track_equal(const moq_track_id_t *a, const moq_track_id_t *b) {
  return a && b && a->type == b->type && strcmp(a->name, b->name) == 0;
}

sent_object_cache_t *transport_sent_cache_find(transport_sent_cache_t *cache,
                                               const moq_track_id_t *track,
                                               uint64_t group_id,
                                               uint64_t object_id) {
  if (!cache || !track)
    return NULL;
  for (size_t i = 0; i < TRANSPORT_SENT_CACHE_SIZE; i++) {
    sent_object_cache_t *entry = &cache->entries[i];
    if (entry->data && track_equal(&entry->track_id, track) &&
        entry->group_id == group_id && entry->object_id == object_id)
      return entry;
  }
  return NULL;
}

void transport_sent_cache_store(transport_sent_cache_t *cache,
                                const moq_object_t *object,
                                uint16_t total_symbols, uint16_t data_symbols,
                                uint16_t symbol_size) {
  if (!cache || !object || !object->data || object->size == 0)
    return;
  sent_object_cache_t *entry = &cache->entries[cache->next_entry];
  uint8_t *copy = malloc(object->size);
  if (!copy)
    return;
  memcpy(copy, object->data, object->size);

  free(entry->data);
  entry->track_id = object->track_id;
  entry->group_id = object->group_id;
  entry->object_id = object->object_id;
  entry->size = object->size;
  entry->priority = object->priority;
  entry->is_keyframe = object->is_keyframe;
  entry->total_symbols = total_symbols;
  entry->data_symbols = data_symbols;
  entry->symbol_size = symbol_size;
  entry->data = copy;
  cache->next_entry = (cache->next_entry + 1U) % TRANSPORT_SENT_CACHE_SIZE;
}

void transport_sent_cache_destroy(transport_sent_cache_t *cache) {
  if (!cache)
    return;
  for (size_t i = 0; i < TRANSPORT_SENT_CACHE_SIZE; i++)
    free(cache->entries[i].data);
  memset(cache, 0, sizeof(*cache));
}

fec_t *transport_fec_cache_get(transport_fec_cache_t *cache, fec_type_t type,
                               size_t data_symbols, size_t parity_symbols,
                               size_t symbol_size) {
  if (!cache || data_symbols == 0 || symbol_size == 0)
    return NULL;
  uint64_t now = get_time_ns();
  size_t lru_index = 0;
  uint64_t oldest = UINT64_MAX;

  for (size_t i = 0; i < TRANSPORT_FEC_CACHE_SIZE; i++) {
    transport_fec_cache_entry_t *entry = &cache->entries[i];
    if (entry->fec && entry->type == type &&
        entry->data_symbols == data_symbols &&
        entry->parity_symbols == parity_symbols &&
        entry->symbol_size == symbol_size) {
      entry->last_used_ns = now;
      return entry->fec;
    }
    if (entry->last_used_ns < oldest) {
      oldest = entry->last_used_ns;
      lru_index = i;
    }
  }

  transport_fec_cache_entry_t *entry = &cache->entries[lru_index];
  fec_t *replacement =
      fec_create_ex(type, data_symbols, parity_symbols, symbol_size);
  if (!replacement)
    return NULL;
  fec_destroy(entry->fec);
  entry->type = type;
  entry->data_symbols = data_symbols;
  entry->parity_symbols = parity_symbols;
  entry->symbol_size = symbol_size;
  entry->fec = replacement;
  entry->last_used_ns = now;
  return replacement;
}

void transport_fec_cache_destroy(transport_fec_cache_t *cache) {
  if (!cache)
    return;
  for (size_t i = 0; i < TRANSPORT_FEC_CACHE_SIZE; i++)
    fec_destroy(cache->entries[i].fec);
  memset(cache, 0, sizeof(*cache));
}
