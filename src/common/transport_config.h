#ifndef QLINQ_TRANSPORT_CONFIG_H
#define QLINQ_TRANSPORT_CONFIG_H

#include "transport.h"

#include <stdbool.h>
#include <stddef.h>

bool transport_limits_resolve(const transport_limits_t *configured,
                              transport_limits_t *resolved, char *error,
                              size_t error_capacity);

#endif
