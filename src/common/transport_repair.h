#ifndef QLINQ_TRANSPORT_REPAIR_H
#define QLINQ_TRANSPORT_REPAIR_H

#include "transport_fec_state.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TRANSPORT_REPAIR_MAX_SYMBOLS 64U

typedef struct {
  uint16_t indices[TRANSPORT_REPAIR_MAX_SYMBOLS];
  uint8_t *symbols;
  size_t count;
  uint16_t total_symbols;
  uint16_t symbol_size;
} transport_repair_batch_t;

bool transport_repair_build(transport_fec_cache_t *fec_cache,
                            const sent_object_cache_t *object,
                            bool whole_object, const uint16_t *missing,
                            size_t missing_count,
                            transport_repair_batch_t *batch);
void transport_repair_batch_destroy(transport_repair_batch_t *batch);

#endif
