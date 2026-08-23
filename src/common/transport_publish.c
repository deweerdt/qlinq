#include "transport_publish.h"

#include "fec.h"
#include "portable_sockets.h"
#include "transport_fec_state.h"
#include "transport_scheduler.h"
#include "transport_stream.h"
#include "transport_subscriptions.h"
#include "transport_tracks.h"
#include "transport_wire.h"

#include "quicly/sendstate.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static transport_publish_result_t
publish_datagram_to_conn(transport_t *t, transport_conn_t *conn,
                         const moq_object_t *obj,
                         const transport_track_profile_t *profile,
                         size_t symbol_size, size_t data_symbols) {
  transport_schedule_t schedule;
  bool use_fec = profile->fec_enabled || profile->fec_rateless;
  if (!transport_schedule_build(&t->scheduler_context, conn->quic,
                                conn->path_states, t->num_fds, data_symbols,
                                symbol_size, use_fec, obj->priority,
                                &t->round_robin_path, &schedule))
    return TRANSPORT_PUBLISH_ERROR;

  size_t parity_symbols = schedule.parity_symbols;
  size_t total_symbols = data_symbols + parity_symbols;
  if (total_symbols > QLINQ_FEC_MAX_TOTAL_SYMBOLS || total_symbols > UINT16_MAX)
    return TRANSPORT_PUBLISH_INVALID;

  uint8_t **data_blocks =
      transport_arena_alloc(&t->arena, data_symbols * sizeof(*data_blocks));
  uint8_t **parity_blocks =
      transport_arena_alloc(&t->arena, parity_symbols * sizeof(*parity_blocks));
  if (!data_blocks || (parity_symbols > 0 && !parity_blocks)) {
    transport_arena_reset(&t->arena);
    return TRANSPORT_PUBLISH_ERROR;
  }

  for (size_t i = 0; i < data_symbols; i++) {
    size_t offset = i * symbol_size;
    size_t chunk = offset < obj->size ? obj->size - offset : 0;
    if (chunk >= symbol_size) {
      data_blocks[i] = (uint8_t *)obj->data + offset;
    } else {
      data_blocks[i] = transport_arena_alloc(&t->arena, symbol_size);
      if (!data_blocks[i]) {
        transport_arena_reset(&t->arena);
        return TRANSPORT_PUBLISH_ERROR;
      }
      memset(data_blocks[i], 0, symbol_size);
      if (chunk > 0)
        memcpy(data_blocks[i], obj->data + offset, chunk);
    }
  }

  for (size_t i = 0; i < parity_symbols; i++) {
    parity_blocks[i] = transport_arena_alloc(&t->arena, symbol_size);
    if (!parity_blocks[i]) {
      transport_arena_reset(&t->arena);
      return TRANSPORT_PUBLISH_ERROR;
    }
  }

  if (parity_symbols > 0) {
    fec_type_t fec_type =
        total_symbols > 255 || obj->track_id.type == MOQ_TRACK_DATA
            ? FEC_RAPTORQ
            : FEC_REED_SOLOMON;
    if (fec_type == FEC_RAPTORQ && total_symbols <= 255)
      fec_type = FEC_REED_SOLOMON;
    fec_t *fec = transport_fec_cache_get(&t->fec_cache, fec_type, data_symbols,
                                         parity_symbols, symbol_size);
    if (!fec ||
        !fec_encode(fec, (const uint8_t *const *)data_blocks, parity_blocks)) {
      transport_arena_reset(&t->arena);
      return TRANSPORT_PUBLISH_ERROR;
    }
  }

  uint16_t needed[TRANSPORT_MAX_QUIC_PATHS] = {0};
  for (size_t s = 0; s < total_symbols; s++) {
    size_t physical =
        transport_path_select_physical(schedule.paths, t->num_fds, s);
    size_t mapped = transport_path_find_by_link(conn->quic, t->local_addrs,
                                                t->num_fds, physical);
    if (mapped >= TRANSPORT_MAX_QUIC_PATHS ||
        ++needed[mapped] > QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY ||
        conn->queued_datagrams[mapped] >
            QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY - needed[mapped]) {
      transport_arena_reset(&t->arena);
      return TRANSPORT_PUBLISH_BACKPRESSURE;
    }
  }

  uint8_t alias;
  if (transport_subscriptions_find_alias(&conn->subscriptions, &obj->track_id,
                                         &alias) != 0) {
    transport_arena_reset(&t->arena);
    return TRANSPORT_PUBLISH_NO_RECIPIENTS;
  }

  size_t queued = 0;
  for (size_t s = 0; s < total_symbols; s++) {
    size_t pkt_len = QLINQ_WIRE_FEC_HEADER_SIZE + symbol_size;
    uint8_t *pkt_buf = transport_arena_alloc(&t->arena, pkt_len);
    if (!pkt_buf) {
      transport_arena_reset(&t->arena);
      return queued > 0 ? TRANSPORT_PUBLISH_PARTIAL : TRANSPORT_PUBLISH_ERROR;
    }
    size_t physical =
        transport_path_select_physical(schedule.paths, t->num_fds, s);
    size_t mapped = transport_path_find_by_link(conn->quic, t->local_addrs,
                                                t->num_fds, physical);
    if (mapped > UINT8_MAX) {
      transport_arena_reset(&t->arena);
      return queued > 0 ? TRANSPORT_PUBLISH_PARTIAL : TRANSPORT_PUBLISH_ERROR;
    }
    qlinq_wire_fec_header_t header = {.alias = alias,
                                      .is_keyframe = obj->is_keyframe,
                                      .priority = obj->priority,
                                      .path_id = (uint8_t)mapped,
                                      .group_id = obj->group_id,
                                      .object_id = obj->object_id,
                                      .symbol_index = (uint16_t)s,
                                      .total_symbols = (uint16_t)total_symbols,
                                      .data_symbols = (uint16_t)data_symbols,
                                      .symbol_size = (uint16_t)symbol_size,
                                      .original_size = (uint32_t)obj->size,
                                      .send_time_ns = transport_get_time_ns()};
    if (qlinq_wire_encode_fec_header(pkt_buf, pkt_len, &header) !=
        QLINQ_WIRE_OK) {
      transport_arena_reset(&t->arena);
      return queued > 0 ? TRANSPORT_PUBLISH_PARTIAL : TRANSPORT_PUBLISH_ERROR;
    }
    const uint8_t *symbol =
        s < data_symbols ? data_blocks[s] : parity_blocks[s - data_symbols];
    memcpy(pkt_buf + QLINQ_WIRE_FEC_HEADER_SIZE, symbol, symbol_size);
    ptls_iovec_t datagram = ptls_iovec_init(pkt_buf, pkt_len);
    if (!transport_queue_datagram(conn, mapped, datagram)) {
      transport_arena_reset(&t->arena);
      return queued > 0 ? TRANSPORT_PUBLISH_PARTIAL
                        : TRANSPORT_PUBLISH_BACKPRESSURE;
    }
    queued++;
  }

  transport_arena_reset(&t->arena);
  return TRANSPORT_PUBLISH_DELIVERED;
}

bool transport_publish_flush_grouped(transport_t *t) {
  if (t->fec_buf_len == 0)
    return true;

  moq_object_t obj = {.track_id = t->fec_track_id,
                      .group_id = 0,
                      .object_id = t->fec_object_id,
                      .data = t->fec_buf,
                      .size = t->fec_buf_len,
                      .is_keyframe = false,
                      .priority = t->fec_priority};

  t->fec_in_flush = true;
  bool published = transport_publish(t, &obj);
  t->fec_in_flush = false;

  if (!published)
    return false;

  t->fec_object_id++;
  t->fec_buf_len = 0;
  t->fec_first_pkt_time = 0;
  t->fec_pkt_count = 0;
  return true;
}

transport_publish_result_t transport_publish_ex(transport_t *t,
                                                const moq_object_t *obj) {
  if (!transport_owner_ok(t) || !obj ||
      !transport_track_id_valid(&obj->track_id) ||
      (obj->size > 0 && !obj->data))
    return TRANSPORT_PUBLISH_INVALID;

  /* route to grouping buffer if it's data and we're not flushing */
  if (obj->track_id.type == MOQ_TRACK_DATA && !t->fec_in_flush) {
    bool use_fec = false;
    if (t->is_server) {
      for (size_t c = 0; c < t->conn_count; c++) {
        transport_conn_t *conn = t->conns[c];
        if (conn && conn->quic && conn->protocol_ready && conn->authenticated &&
            quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING) {
          const track_subscription_t *subscription =
              transport_subscriptions_find_const(&conn->subscriptions,
                                                 &obj->track_id);
          if (subscription) {
            transport_track_profile_t sub_profile =
                transport_track_profile(&subscription->track_id);
            use_fec = sub_profile.fec_enabled || sub_profile.fec_rateless;
          }
          if (use_fec)
            break;
        }
      }
    } else if (t->client_conn && t->client_conn->protocol_ready &&
               t->client_conn->authenticated) {
      transport_conn_t *conn = t->client_conn;
      const track_subscription_t *subscription =
          transport_subscriptions_find_const(&conn->subscriptions,
                                             &obj->track_id);
      if (subscription) {
        transport_track_profile_t sub_profile =
            transport_track_profile(&subscription->track_id);
        use_fec = sub_profile.fec_enabled || sub_profile.fec_rateless;
      }
    }

    if (use_fec) {
      if (obj->size > TRANSPORT_MAX_FEC_RECORD_SIZE)
        return TRANSPORT_PUBLISH_INVALID;

      if (t->fec_buf_len > 0 &&
          (!transport_track_id_equal(&t->fec_track_id, &obj->track_id) ||
           t->fec_priority != obj->priority)) {
        if (!transport_publish_flush_grouped(t))
          return TRANSPORT_PUBLISH_ERROR;
      }

      if (t->fec_buf_len > 0 &&
          (t->fec_pkt_count >= 4 || obj->size > 16384 - 2 ||
           t->fec_buf_len > 16384 - 2 - obj->size)) {
        if (!transport_publish_flush_grouped(t))
          return TRANSPORT_PUBLISH_ERROR;
      }

      uint64_t now = ptls_get_time.cb(&ptls_get_time);
      if (t->fec_buf_len == 0) {
        t->fec_first_pkt_time = now;
        t->fec_track_id = obj->track_id;
        t->fec_priority = obj->priority;
      }

      if (obj->size > SIZE_MAX - 2 - t->fec_buf_len)
        return TRANSPORT_PUBLISH_INVALID;
      size_t needed = t->fec_buf_len + 2 + obj->size;
      if (needed > t->fec_buf_cap) {
        size_t new_cap = t->fec_buf_cap == 0 ? 4096 : t->fec_buf_cap * 2;
        if (new_cap < t->fec_buf_cap)
          return TRANSPORT_PUBLISH_ERROR;
        while (new_cap < needed) {
          if (new_cap > SIZE_MAX / 2)
            return TRANSPORT_PUBLISH_ERROR;
          new_cap *= 2;
        }
        uint8_t *new_buf = realloc(t->fec_buf, new_cap);
        if (!new_buf) {
          return TRANSPORT_PUBLISH_ERROR;
        }
        t->fec_buf = new_buf;
        t->fec_buf_cap = new_cap;
      }

      uint16_t len_be = htons((uint16_t)obj->size);
      memcpy(t->fec_buf + t->fec_buf_len, &len_be, 2);
      memcpy(t->fec_buf + t->fec_buf_len + 2, obj->data, obj->size);
      t->fec_buf_len = needed;
      t->fec_pkt_count++;

      if (t->fec_pkt_count >= 4 || t->fec_buf_len >= 16384)
        return transport_publish_flush_grouped(t) ? TRANSPORT_PUBLISH_DELIVERED
                                                  : TRANSPORT_PUBLISH_ERROR;
      return TRANSPORT_PUBLISH_BUFFERED;
    }
  }

  transport_track_profile_t profile = transport_track_profile(&obj->track_id);

  /* route over reliable stream if requested by profile */
  if (profile.reliable) {
    if (obj->size > t->limits.max_reliable_object_size)
      return TRANSPORT_PUBLISH_INVALID;
    size_t active_count =
        t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
    size_t eligible = 0;
    size_t delivered = 0;
    bool failed = false;
    for (size_t i = 0; i < active_count; ++i) {
      transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
      if (!conn || !conn->quic || !conn->protocol_ready ||
          !conn->authenticated ||
          quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING)
        continue;
      if (t->is_server && !transport_subscriptions_contains(
                              &conn->subscriptions, &obj->track_id))
        continue;
      eligible++;
      if (obj->size > conn->negotiated_limits.max_reliable_object_size) {
        failed = true;
        continue;
      }

      track_subscription_t *sub =
          transport_subscriptions_find(&conn->subscriptions, &obj->track_id);
      if (sub) {
        if (!sub->stream ||
            !quicly_sendstate_is_open(&sub->stream->sendstate)) {
          sub->stream = NULL;
          int err = quicly_open_stream(conn->quic, &sub->stream,
                                       1); /* 1 = unidirectional */
          if (err == 0 && sub->stream) {
            quicly_debug_printf(conn->quic,
                                "Opened QUIC Stream %" PRIu64
                                " for MoQ track alias %d",
                                sub->stream->stream_id, sub->alias);
          } else {
            fprintf(stderr, "Failed to open reliable track stream: %d\n", err);
            failed = true;
            continue;
          }
        }

        uint8_t alias = sub->alias;
        if (!transport_stream_write_object_frame(sub->stream, alias, obj)) {
          failed = true;
          continue;
        }
      } else {
        if (!transport_send_unicast(t, conn, obj->data, obj->size)) {
          failed = true;
          continue;
        }
      }
      delivered++;
    }
    if (failed)
      return delivered > 0 ? TRANSPORT_PUBLISH_PARTIAL
                           : TRANSPORT_PUBLISH_ERROR;
    return eligible == 0 ? TRANSPORT_PUBLISH_NO_RECIPIENTS
                         : TRANSPORT_PUBLISH_DELIVERED;
  }

  /* audio, video, text tracks go over unreliable datagram frames with FEC */
  size_t data_size = obj->size;
  if (data_size == 0 || data_size > t->limits.max_fec_object_size)
    return TRANSPORT_PUBLISH_INVALID;
  size_t symbol_size = transport_get_datagram_symbol_size(t);
  size_t data_symbols = (data_size + symbol_size - 1) / symbol_size;
  if (data_symbols == 0)
    data_symbols = 1;

  size_t active_count =
      t->is_server ? t->conn_count : (t->client_conn ? 1U : 0U);
  size_t eligible = 0;
  size_t delivered = 0;
  bool partially_queued = false;
  transport_publish_result_t failure = TRANSPORT_PUBLISH_ERROR;

  for (size_t c = 0; c < active_count; c++) {
    transport_conn_t *conn = t->is_server ? t->conns[c] : t->client_conn;
    if (!conn || !conn->quic || !conn->protocol_ready || !conn->authenticated ||
        quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING ||
        (t->is_server && !transport_subscriptions_contains(&conn->subscriptions,
                                                           &obj->track_id)))
      continue;
    eligible++;
    if (obj->size > conn->negotiated_limits.max_fec_object_size) {
      failure = TRANSPORT_PUBLISH_INVALID;
      continue;
    }
    transport_publish_result_t result = publish_datagram_to_conn(
        t, conn, obj, &profile, symbol_size, data_symbols);
    if (result == TRANSPORT_PUBLISH_DELIVERED) {
      delivered++;
    } else if (result == TRANSPORT_PUBLISH_NO_RECIPIENTS) {
      eligible--;
    } else {
      if (result == TRANSPORT_PUBLISH_PARTIAL)
        partially_queued = true;
      if (result == TRANSPORT_PUBLISH_BACKPRESSURE)
        failure = TRANSPORT_PUBLISH_BACKPRESSURE;
    }
  }

  if ((delivered > 0 || partially_queued) &&
      obj->track_id.type == MOQ_TRACK_DATA)
    transport_sent_cache_store(&t->sent_cache, obj, (uint16_t)data_symbols,
                               (uint16_t)data_symbols, (uint16_t)symbol_size);

  if (partially_queued || (delivered > 0 && delivered != eligible))
    return TRANSPORT_PUBLISH_PARTIAL;
  if (delivered == 0)
    return eligible == 0 ? TRANSPORT_PUBLISH_NO_RECIPIENTS : failure;
  return TRANSPORT_PUBLISH_DELIVERED;
}

bool transport_publish(transport_t *t, const moq_object_t *obj) {
  transport_publish_result_t result = transport_publish_ex(t, obj);
  return result == TRANSPORT_PUBLISH_DELIVERED ||
         result == TRANSPORT_PUBLISH_BUFFERED ||
         result == TRANSPORT_PUBLISH_NO_RECIPIENTS;
}
