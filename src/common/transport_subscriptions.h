#ifndef QLINQ_TRANSPORT_SUBSCRIPTIONS_H
#define QLINQ_TRANSPORT_SUBSCRIPTIONS_H

#include "transport.h"

#include "quicly.h"

#define TRANSPORT_MAX_SUBSCRIPTIONS 32U

typedef struct {
  moq_track_id_t track_id;
  uint8_t alias;
  bool active;
  quicly_stream_t *stream;
} track_subscription_t;

typedef struct {
  track_subscription_t entries[TRANSPORT_MAX_SUBSCRIPTIONS];
} transport_subscription_table_t;

int transport_subscriptions_find_by_alias(
    const transport_subscription_table_t *table, uint8_t alias,
    moq_track_id_t *out_track);
int transport_subscriptions_find_alias(
    const transport_subscription_table_t *table, const moq_track_id_t *track,
    uint8_t *out_alias);
track_subscription_t *
transport_subscriptions_find(transport_subscription_table_t *table,
                             const moq_track_id_t *track);
const track_subscription_t *
transport_subscriptions_find_const(const transport_subscription_table_t *table,
                                   const moq_track_id_t *track);
bool transport_subscriptions_contains(
    const transport_subscription_table_t *table, const moq_track_id_t *track);
bool transport_subscriptions_add(transport_subscription_table_t *table,
                                 moq_track_type_t type, uint8_t flags,
                                 const char *name, uint8_t alias);
void transport_subscriptions_remove(transport_subscription_table_t *table,
                                    moq_track_type_t type, const char *name);
void transport_subscriptions_clear_stream(transport_subscription_table_t *table,
                                          quicly_stream_t *stream);
bool transport_subscriptions_bind_stream(transport_subscription_table_t *table,
                                         uint8_t alias,
                                         quicly_stream_t *stream);
int transport_subscriptions_next_alias(
    const transport_subscription_table_t *table, int first_dynamic_alias);

#endif
