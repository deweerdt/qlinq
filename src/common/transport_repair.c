#include "transport_repair.h"

#include <stdlib.h>
#include <string.h>

void transport_repair_batch_destroy(transport_repair_batch_t *batch) {
  if (!batch)
    return;
  free(batch->symbols);
  memset(batch, 0, sizeof(*batch));
}

static bool append_unique(transport_repair_batch_t *batch, uint16_t index) {
  for (size_t i = 0; i < batch->count; i++) {
    if (batch->indices[i] == index)
      return true;
  }
  if (batch->count >= TRANSPORT_REPAIR_MAX_SYMBOLS)
    return false;
  batch->indices[batch->count++] = index;
  return true;
}

bool transport_repair_build(transport_fec_cache_t *fec_cache,
                            const sent_object_cache_t *object,
                            bool whole_object, const uint16_t *missing,
                            size_t missing_count,
                            transport_repair_batch_t *batch) {
  if (!fec_cache || !object || !object->data || object->size == 0 || !batch ||
      object->data_symbols == 0 || object->symbol_size == 0 ||
      (!whole_object && (!missing || missing_count == 0)))
    return false;
  memset(batch, 0, sizeof(*batch));
  batch->symbol_size = object->symbol_size;

  if (whole_object) {
    size_t count = object->data_symbols;
    if (count > TRANSPORT_REPAIR_MAX_SYMBOLS)
      count = TRANSPORT_REPAIR_MAX_SYMBOLS;
    for (size_t i = 0; i < count; i++)
      batch->indices[batch->count++] = (uint16_t)i;
  } else {
    size_t count = missing_count;
    if (count > TRANSPORT_REPAIR_MAX_SYMBOLS)
      count = TRANSPORT_REPAIR_MAX_SYMBOLS;
    for (size_t i = 0; i < count; i++) {
      if (missing[i] >= QLINQ_FEC_MAX_TOTAL_SYMBOLS ||
          !append_unique(batch, missing[i]))
        return false;
    }
  }
  if (batch->count == 0)
    return false;

  uint16_t highest = 0;
  for (size_t i = 0; i < batch->count; i++) {
    if (batch->indices[i] > highest)
      highest = batch->indices[i];
  }
  size_t parity_symbols = highest >= object->data_symbols
                              ? (size_t)highest - object->data_symbols + 1U
                              : 0U;
  bool rateless = (object->track_id.flags & MOQ_TRACK_FLAG_FEC_RATELESS) != 0;
  size_t original_parity = object->total_symbols >= object->data_symbols
                               ? object->total_symbols - object->data_symbols
                               : 0;
  if (!rateless && parity_symbols < original_parity)
    parity_symbols = original_parity;
  size_t total_symbols = object->data_symbols + parity_symbols;
  if (total_symbols > UINT16_MAX)
    return false;

  if (batch->count > SIZE_MAX / object->symbol_size)
    return false;
  batch->symbols = calloc(batch->count, object->symbol_size);
  if (!batch->symbols)
    return false;

  uint8_t **data_blocks = calloc(object->data_symbols, sizeof(*data_blocks));
  uint8_t *data_storage = calloc(object->data_symbols, object->symbol_size);
  uint8_t **parity_blocks = parity_symbols > 0
                                ? calloc(parity_symbols, sizeof(*parity_blocks))
                                : NULL;
  uint8_t *parity_storage =
      parity_symbols > 0 ? calloc(parity_symbols, object->symbol_size) : NULL;
  if (!data_blocks || !data_storage ||
      (parity_symbols > 0 && (!parity_blocks || !parity_storage))) {
    free(data_blocks);
    free(data_storage);
    free(parity_blocks);
    free(parity_storage);
    transport_repair_batch_destroy(batch);
    return false;
  }

  for (size_t i = 0; i < object->data_symbols; i++) {
    data_blocks[i] = data_storage + i * object->symbol_size;
    size_t offset = i * object->symbol_size;
    size_t chunk = offset < object->size ? object->size - offset : 0;
    if (chunk > object->symbol_size)
      chunk = object->symbol_size;
    if (chunk > 0)
      memcpy(data_blocks[i], object->data + offset, chunk);
  }

  bool encoded = true;
  if (parity_symbols > 0) {
    for (size_t i = 0; i < parity_symbols; i++)
      parity_blocks[i] = parity_storage + i * object->symbol_size;
    fec_type_t type =
        rateless || total_symbols > 255 ? FEC_RAPTORQ : FEC_REED_SOLOMON;
    fec_t *fec = transport_fec_cache_get(fec_cache, type, object->data_symbols,
                                         parity_symbols, object->symbol_size);
    encoded = fec && fec_encode(fec, (const uint8_t *const *)data_blocks,
                                parity_blocks);
  }

  if (encoded) {
    for (size_t i = 0; i < batch->count; i++) {
      uint16_t index = batch->indices[i];
      const uint8_t *source = index < object->data_symbols
                                  ? data_blocks[index]
                                  : parity_blocks[index - object->data_symbols];
      memcpy(batch->symbols + i * object->symbol_size, source,
             object->symbol_size);
    }
  }
  free(data_blocks);
  free(data_storage);
  free(parity_blocks);
  free(parity_storage);
  if (!encoded) {
    transport_repair_batch_destroy(batch);
    return false;
  }
  batch->total_symbols = (uint16_t)total_symbols;
  return true;
}
