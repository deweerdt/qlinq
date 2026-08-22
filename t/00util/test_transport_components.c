#include "transport_fec_state.h"
#include "transport_memory.h"
#include "transport_paths.h"
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

  path_t paths[3] = {{.x = 2}, {.x = 1}, {.x = 3}};
  CHECK(transport_path_select_physical(paths, 3, 0) == 0 &&
            transport_path_select_physical(paths, 3, 2) == 1 &&
            transport_path_select_physical(paths, 3, 5) == 2,
        "physical path selection");

  const uint8_t object_data[] = {1, 2, 3, 4};
  moq_object_t object = {.track_id = track,
                         .group_id = 10,
                         .object_id = 20,
                         .data = object_data,
                         .size = sizeof(object_data),
                         .priority = 2};
  transport_sent_cache_t sent_cache = {0};
  transport_sent_cache_store(&sent_cache, &object, 4, 3, 1200);
  sent_object_cache_t *cached =
      transport_sent_cache_find(&sent_cache, &track, 10, 20);
  CHECK(cached && cached->size == sizeof(object_data) && cached->data[3] == 4,
        "sent-object cache roundtrip");
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
