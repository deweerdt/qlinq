#include "transport_config.h"
#include "transport_egress.h"
#include "transport_fec_state.h"
#include "transport_memory.h"
#include "transport_paths.h"
#include "transport_repair.h"
#include "transport_scheduler.h"
#include "transport_subscriptions.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "transport component test failed: %s\n", message);       \
      return 1;                                                                \
    }                                                                          \
  } while (0)

int main(void) {
  transport_limits_t configured = {0};
  transport_limits_t resolved_limits;
  char limit_error[128];
  CHECK(transport_limits_resolve(&configured, &resolved_limits, limit_error,
                                 sizeof(limit_error)),
        "default limit resolution");
  CHECK(resolved_limits.max_connections == TRANSPORT_DEFAULT_MAX_CONNECTIONS &&
            resolved_limits.max_subscriptions_per_connection ==
                TRANSPORT_DEFAULT_MAX_SUBSCRIPTIONS &&
            resolved_limits.max_udp_payload_size == 1280,
        "default limits");
  configured.max_egress_packets_per_socket = 63;
  CHECK(!transport_limits_resolve(&configured, &resolved_limits, limit_error,
                                  sizeof(limit_error)),
        "unsafe egress limit rejection");

  transport_egress_t egress;
  CHECK(transport_egress_init(&egress, 64, 64U * 1500U), "egress init");
  CHECK(transport_egress_can_accept(&egress, 64, 64U * 1500U) &&
            !transport_egress_can_accept(&egress, 65, 64U * 1500U),
        "egress reservation bounds");
  transport_egress_destroy(&egress);

  arena_t arena;
  CHECK(transport_arena_init(&arena, 64), "arena init");
  CHECK(transport_arena_alloc(&arena, 16) != NULL, "arena allocation");
  CHECK(transport_arena_alloc(&arena, 128) != NULL, "arena fallback");
  CHECK(arena.fallback_count == 1, "arena fallback ownership");
  transport_arena_reset(&arena);
  CHECK(arena.offset == 0 && arena.fallback_count == 0, "arena reset");
  transport_arena_destroy(&arena);

  frame_assembler_t assembler = {0};
  CHECK(transport_assembler_grow(&assembler, 2, 8), "assembler allocation");
  CHECK(transport_assembler_capacity_bytes(&assembler) ==
            transport_assembler_required_bytes(2, 8),
        "assembler memory accounting");
  memset(assembler.buffers[0], 0x5a, 8);
  assembler.received_mask[0] = true;
  assembler.total_symbols = 2;
  assembler.symbol_size = 8;
  CHECK(transport_assembler_grow(&assembler, 4, 16), "assembler growth");
  CHECK(assembler.buffers[0][0] == 0x5a && assembler.received_mask[0],
        "assembler growth preserves state");
  transport_assembler_release(&assembler);
  CHECK(assembler.buffers == NULL, "assembler release");

  transport_subscription_table_t subscriptions = {0};
  moq_track_id_t track = {
      .type = MOQ_TRACK_DATA, .flags = MOQ_TRACK_FLAG_RELIABLE, .name = "data"};
  CHECK(transport_subscriptions_add(&subscriptions, track.type, track.flags,
                                    track.name, 8),
        "subscription add");
  uint8_t alias = 0;
  CHECK(transport_subscriptions_find_alias(&subscriptions, &track, &alias) ==
                0 &&
            alias == 8,
        "subscription alias lookup");
  moq_track_id_t resolved;
  CHECK(transport_subscriptions_find_by_alias(&subscriptions, 8, &resolved) ==
                0 &&
            strcmp(resolved.name, track.name) == 0,
        "subscription track lookup");
  quicly_stream_t *fake_stream = (quicly_stream_t *)(uintptr_t)1;
  CHECK(transport_subscriptions_bind_stream(&subscriptions, 8, fake_stream),
        "subscription stream binding");
  transport_subscriptions_clear_stream(&subscriptions, fake_stream);
  CHECK(transport_subscriptions_find(&subscriptions, &track)->stream == NULL,
        "subscription stream clearing");
  CHECK(transport_subscriptions_next_alias(&subscriptions, 8) == 9,
        "subscription next alias");
  transport_subscriptions_remove(&subscriptions, track.type, track.name);
  CHECK(!transport_subscriptions_contains(&subscriptions, &track),
        "subscription removal");
  transport_subscriptions_destroy(&subscriptions);

  transport_subscription_table_t bounded_subscriptions = {0};
  CHECK(transport_subscriptions_init(&bounded_subscriptions, 1),
        "bounded subscription init");
  CHECK(transport_subscriptions_add(&bounded_subscriptions, MOQ_TRACK_DATA, 0,
                                    "one", 8) &&
            !transport_subscriptions_add(&bounded_subscriptions, MOQ_TRACK_DATA,
                                         0, "alias-collision", 8) &&
            !transport_subscriptions_add(&bounded_subscriptions, MOQ_TRACK_DATA,
                                         0, "two", 9),
        "subscription capacity");
  transport_subscriptions_destroy(&bounded_subscriptions);

  path_t paths[3] = {{.x = 2}, {.x = 1}, {.x = 3}};
  CHECK(transport_path_select_physical(paths, 3, 0) == 0 &&
            transport_path_select_physical(paths, 3, 2) == 1 &&
            transport_path_select_physical(paths, 3, 5) == 2,
        "physical path selection");

  path_state_t path_states[2] = {
      {.b_ewma = FP_FROM_INT(100), .l_ewma = FP_FROM_FLOAT(0.01f)},
      {.b_ewma = FP_FROM_INT(50), .l_ewma = FP_FROM_FLOAT(0.02f)}};
  pathflow_context_t scheduler_context = {0};
  size_t round_robin = 0;
  transport_schedule_t schedule;
  CHECK(transport_schedule_build(&scheduler_context, NULL, path_states, 2, 5,
                                 1100, false, 1, &round_robin, &schedule) &&
            schedule.paths[0].x == 3 && schedule.paths[1].x == 2 &&
            schedule.parity_symbols == 0,
        "non-FEC schedule distribution");
  CHECK(transport_schedule_build(&scheduler_context, NULL, path_states, 2, 1,
                                 1100, true, 1, &round_robin, &schedule) &&
            schedule.paths[0].x == 1 && round_robin == 1,
        "single-symbol round robin schedule");

  const uint8_t object_data[] = {1, 2, 3, 4};
  moq_object_t object = {.track_id = track,
                         .group_id = 10,
                         .object_id = 20,
                         .data = object_data,
                         .size = sizeof(object_data),
                         .priority = 2};
  transport_sent_cache_t sent_cache = {0};
  transport_sent_cache_store(&sent_cache, &object, 3, 2, 2);
  sent_object_cache_t *cached =
      transport_sent_cache_find(&sent_cache, &track, 10, 20);
  CHECK(cached && cached->size == sizeof(object_data) && cached->data[3] == 4,
        "sent-object cache roundtrip");

  uint16_t missing_symbol = 1;
  transport_repair_batch_t repair;
  transport_fec_cache_t repair_fec_cache = {0};
  CHECK(transport_repair_build(&repair_fec_cache, cached, false,
                               &missing_symbol, 1, &repair),
        "repair batch build");
  CHECK(repair.count == 1 && repair.indices[0] == 1 &&
            repair.symbols[0] == object_data[2],
        "repair returns requested data symbol");
  transport_repair_batch_destroy(&repair);
  CHECK(transport_repair_build(&repair_fec_cache, cached, true, NULL, 0,
                               &repair) &&
            repair.count == cached->data_symbols,
        "whole-object repair is bounded data retransmission");
  transport_repair_batch_destroy(&repair);
  transport_fec_cache_destroy(&repair_fec_cache);
  transport_sent_cache_destroy(&sent_cache);

  transport_fec_cache_t fec_cache = {0};
  fec_t *fec = transport_fec_cache_get(&fec_cache, FEC_REED_SOLOMON, 2, 1, 8);
  CHECK(fec != NULL, "FEC cache creation");
  CHECK(transport_fec_cache_get(&fec_cache, FEC_REED_SOLOMON, 2, 1, 8) == fec,
        "FEC cache reuse");
  transport_fec_cache_destroy(&fec_cache);

  printf("===TRANSPORT COMPONENTS OK===\n");
  return 0;
}
