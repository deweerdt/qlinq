/* fec.h
 *
 * design philosophy:
 * this interface abstracts forward error correction (fec) algorithms,
 * allowing us to swap between reed-solomon (nanors) and raptorq (nanorq)
 * depending on packet block sizes, network loss patterns, and target
 * resolutions.
 */

#ifndef FEC_H
#define FEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct fec_t fec_t;

/* A fec_t instance is reusable but must be confined to one thread at a time. */

typedef enum { FEC_REED_SOLOMON, FEC_RAPTORQ } fec_type_t;

/* create a forward error correction instance */
fec_t *fec_create_ex(fec_type_t type, size_t data_symbols,
                     size_t parity_symbols, size_t symbol_size);
fec_t *fec_create(size_t data_symbols, size_t parity_symbols,
                  size_t symbol_size);
void fec_destroy(fec_t *f);

/* encode data symbols and output parity symbols */
bool fec_encode(fec_t *f, const uint8_t *const *data_blocks,
                uint8_t *const *parity_blocks);

/* decode received symbols. missing_mask represents indices of lost blocks */
bool fec_decode(fec_t *f, uint8_t *const *blocks, const bool *missing_mask);

#endif /* FEC_H */
