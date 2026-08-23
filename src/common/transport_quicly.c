/* transport_quicly.c */

#include "fec.h"
#include "ifmon.h"
#include "pathflow.h"
#include "portable_sockets.h"
#include "transport.h"
#include "transport_fec_state.h"
#include "transport_memory.h"
#include "transport_paths.h"
#include "transport_repair.h"
#include "transport_scheduler.h"
#include "transport_stream.h"
#include "transport_subscriptions.h"
#include "transport_tls.h"
#include "transport_udp.h"
#include "transport_wire.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <net/if.h>
#endif
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/sendstate.h"
#include "quicly/streambuf.h"

static uint64_t get_time_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

#define MAX_CONNECTIONS 32
#define ASSEMBLER_CACHE_SIZE 8
#define FEC_MAX_TOTAL_SYMBOLS 1024
#define FEC_MAX_SYMBOL_SIZE 1500
#define FEC_MAX_OBJECT_SIZE (1024U * 1024U)
#define FEC_ASSEMBLER_TIMEOUT_MS 2000
#define FEC_NACK_DELAY_MS 25
#define FEC_REPAIR_REQUESTS_PER_SECOND 16U
#define FEC_REPAIR_DEDUP_MS 25
#define QUICLY_PATH_DATAGRAM_QUEUE_CAPACITY 256
#define TRANSPORT_ASSEMBLER_MEMORY_BUDGET (64U * 1024U * 1024U)

typedef struct {
  uint64_t last_seen;
  uint64_t pending_base;
  uint32_t pending_mask;
  uint64_t group_id;
  int64_t detected_at_ms;
} object_gap_state_t;

struct transport_t {
  transport_callback_t callback;
  void *user_data;
  bool is_server;
  int fds[TRANSPORT_MAX_PATHS];
  size_t num_fds;
  struct sockaddr_storage local_addrs[TRANSPORT_MAX_PATHS];
  socklen_t local_addrs_len[TRANSPORT_MAX_PATHS];
  uint32_t local_ifindices[TRANSPORT_MAX_PATHS];

  /* client connection */
  struct sockaddr_storage remote_addrs[TRANSPORT_MAX_PATHS];
  socklen_t remote_addrs_len[TRANSPORT_MAX_PATHS];
  size_t num_remote_addrs;
  quicly_context_t quic_ctx;
  ptls_context_t tls_ctx;
  ptls_openssl_sign_certificate_t sign_cert;
  quicly_cid_plaintext_t next_cid;

  uint64_t last_pathflow_update;
  pathflow_context_t scheduler_context;
  size_t round_robin_path;

  /* server connections list */
  transport_conn_t *conns[MAX_CONNECTIONS];
  size_t conn_count;

  /* client connection */
  transport_conn_t *client_conn;

  /* stream open callback payload */
  quicly_stream_open_t stream_open;
  ptls_openssl_verify_certificate_t verifier;
  bool verifier_initialized;
  quicly_receive_datagram_frame_t receive_datagram;

  /* sent object history cache for NACK retransmissions */
  transport_sent_cache_t sent_cache;

  /* simulated packet loss */
  uint8_t simulated_loss_rate;

  /* pre-allocated transport memory arena */
  arena_t arena;

  /* FEC Packet Grouping Buffer */
  uint8_t *fec_buf;
  size_t fec_buf_len;
  size_t fec_buf_cap;
  uint64_t fec_first_pkt_time;
  moq_track_id_t fec_track_id;
  uint64_t fec_object_id;
  uint32_t fec_pkt_count;
  uint8_t fec_priority;
  bool fec_in_flush;

  /* ifmon integration */
  ifmon_watcher_t ifmon_w;
  int ifmon_pipe[2];

  /* fec cache for zero-allocation hot path */
  transport_fec_cache_t fec_cache;
  size_t assembler_memory_bytes;
};

static void release_assembler(transport_t *t, frame_assembler_t *assembler) {
  if (!t || !assembler)
    return;
  size_t bytes = transport_assembler_capacity_bytes(assembler);
  if (bytes <= t->assembler_memory_bytes)
    t->assembler_memory_bytes -= bytes;
  else
    t->assembler_memory_bytes = 0;
  transport_assembler_release(assembler);
}

static bool grow_assembler(transport_t *t, frame_assembler_t *assembler,
                           uint16_t symbols, uint16_t symbol_size) {
  if (!t || !assembler)
    return false;
  size_t old_bytes = transport_assembler_capacity_bytes(assembler);
  size_t new_bytes = transport_assembler_required_bytes(symbols, symbol_size);
  if (assembler->capacity_symbols > symbols ||
      assembler->capacity_symbol_size > symbol_size) {
    uint16_t actual_symbols = assembler->capacity_symbols > symbols
                                  ? assembler->capacity_symbols
                                  : symbols;
    uint16_t actual_symbol_size = assembler->capacity_symbol_size > symbol_size
                                      ? assembler->capacity_symbol_size
                                      : symbol_size;
    new_bytes =
        transport_assembler_required_bytes(actual_symbols, actual_symbol_size);
  }
  size_t used_without_old = old_bytes <= t->assembler_memory_bytes
                                ? t->assembler_memory_bytes - old_bytes
                                : t->assembler_memory_bytes;
  if (new_bytes > TRANSPORT_ASSEMBLER_MEMORY_BUDGET - used_without_old)
    return false;
  if (!transport_assembler_grow(assembler, symbols, symbol_size))
    return false;
  t->assembler_memory_bytes =
      used_without_old + transport_assembler_capacity_bytes(assembler);
  return true;
}

struct transport_conn_t {
  transport_t *transport;
  quicly_conn_t *quic;
  uint32_t id;
  transport_subscription_table_t subscriptions;
  bool handshake_complete;
  bool authenticated;

  /* client control stream */
  quicly_stream_t *stream;

  /* incoming datagram assembler cache */
  frame_assembler_t assemblers[ASSEMBLER_CACHE_SIZE];
  size_t assembler_index;
  object_gap_state_t object_gaps[UINT8_MAX + 1U];
  uint16_t queued_datagrams[TRANSPORT_MAX_QUIC_PATHS];
  path_state_t path_states[TRANSPORT_MAX_PATHS];
  int64_t min_owd_ns[TRANSPORT_MAX_PATHS];
  fp_t latest_owd_fp[TRANSPORT_MAX_PATHS];
  uint64_t last_telemetry_s_ns[TRANSPORT_MAX_PATHS];
  uint64_t last_telemetry_r_ns[TRANSPORT_MAX_PATHS];
  bool path_state_overridden[TRANSPORT_MAX_PATHS];
  int64_t repair_window_start_ms;
  uint16_t repair_requests_in_window;
  int64_t last_repair_ms;
  uint64_t last_repair_group_id;
  uint64_t last_repair_object_id;
  uint8_t last_repair_alias;
  uint8_t last_repair_flags;
};

static bool queue_datagram(transport_conn_t *conn, size_t path_index,
                           ptls_iovec_t datagram) {
  quicly_path_stats_t path_stats;
  if (!conn || !conn->quic || path_index >= TRANSPORT_MAX_QUIC_PATHS ||
      quicly_get_path_stats(conn->quic, path_index, &path_stats) != 0 ||
      conn->queued_datagrams[path_index] >= QUICLY_PATH_DATAGRAM_QUEUE_CAPACITY)
    return false;
  quicly_send_datagram_frames_path(conn->quic, path_index, &datagram, 1);
  conn->queued_datagrams[path_index]++;
  return true;
}

static bool valid_track_type(uint8_t type) {
  return type == MOQ_TRACK_VIDEO || type == MOQ_TRACK_AUDIO ||
         type == MOQ_TRACK_INPUT || type == MOQ_TRACK_TEXT ||
         type == MOQ_TRACK_DATA || type == MOQ_TRACK_TELEMETRY;
}

static void close_wire_error(transport_conn_t *conn,
                             qlinq_wire_result_t result) {
  const char *reason = result == QLINQ_WIRE_UNSUPPORTED_VERSION
                           ? "protocol version mismatch"
                           : "protocol error: malformed frame";
  quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL, reason);
}

static bool repair_request_allowed(transport_conn_t *conn,
                                   const qlinq_wire_nack_t *nack) {
  int64_t now = transport_get_time_ms();
  if (conn->repair_window_start_ms == 0 ||
      now - conn->repair_window_start_ms >= 1000) {
    conn->repair_window_start_ms = now;
    conn->repair_requests_in_window = 0;
  }
  if (conn->repair_requests_in_window >= FEC_REPAIR_REQUESTS_PER_SECOND)
    return false;
  if (conn->last_repair_ms != 0 &&
      now - conn->last_repair_ms < FEC_REPAIR_DEDUP_MS &&
      conn->last_repair_alias == nack->alias &&
      conn->last_repair_flags == nack->flags &&
      conn->last_repair_group_id == nack->group_id &&
      conn->last_repair_object_id == nack->object_id)
    return false;
  conn->repair_requests_in_window++;
  conn->last_repair_ms = now;
  conn->last_repair_alias = nack->alias;
  conn->last_repair_flags = nack->flags;
  conn->last_repair_group_id = nack->group_id;
  conn->last_repair_object_id = nack->object_id;
  return true;
}

/* Parse complete, versioned control frames from the stream buffer. */
static void parse_control_messages(transport_t *t, transport_conn_t *conn,
                                   quicly_stream_t *stream) {
  while (1) {
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    if (input.len == 0)
      break;

    qlinq_wire_frame_t frame;
    qlinq_wire_result_t result = qlinq_wire_decode_frame(
        input.base, input.len, TRANSPORT_WIRE_MAX_STREAM_PAYLOAD, &frame);
    if (result == QLINQ_WIRE_NEED_MORE)
      break;
    if (result != QLINQ_WIRE_OK) {
      close_wire_error(conn, result);
      break;
    }

    input = ptls_iovec_init(frame.payload, frame.payload_len);
    uint8_t type = frame.type;
    if (type == QLINQ_WIRE_SUBSCRIBE || type == QLINQ_WIRE_UNSUBSCRIBE ||
        type == QLINQ_WIRE_KEYFRAME_REQUEST) {
      qlinq_wire_track_t wire_track;
      if (qlinq_wire_decode_track(input.base, input.len, &wire_track) !=
          QLINQ_WIRE_OK) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: invalid track");
        break;
      }

      if (!conn->authenticated) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_AUTHENTICATION,
                     "unauthorized");
        break;
      }

      uint8_t alias = wire_track.alias;
      uint8_t track_type = wire_track.track_type;
      uint8_t flags = wire_track.flags;
      if (!valid_track_type(track_type) ||
          (flags & ~(MOQ_TRACK_FLAG_RELIABLE | MOQ_TRACK_FLAG_FEC_ENABLED |
                     MOQ_TRACK_FLAG_FEC_RATELESS)) != 0) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: invalid track");
        break;
      }

      moq_track_id_t parsed_track = {.type = (moq_track_type_t)track_type,
                                     .flags = flags};
      strcpy(parsed_track.name, wire_track.name);

      if (type == QLINQ_WIRE_SUBSCRIBE) {
        quicly_debug_printf(
            conn->quic,
            "Subscription mapping: track '%s' (type %d) mapped to alias %d",
            wire_track.name, track_type, alias);
        if (!transport_subscriptions_add(&conn->subscriptions,
                                         (moq_track_type_t)track_type, flags,
                                         wire_track.name, alias)) {
          quicly_close(conn->quic, TRANSPORT_APP_ERROR_RESOURCE_LIMIT,
                       "protocol error: too many tracks");
          break;
        }
      } else if (type == QLINQ_WIRE_UNSUBSCRIBE) {
        transport_subscriptions_remove(&conn->subscriptions,
                                       (moq_track_type_t)track_type,
                                       wire_track.name);
      }

      transport_event_type_t ev_type = TRANSPORT_EVENT_SUBSCRIBE;
      if (type == QLINQ_WIRE_UNSUBSCRIBE) {
        ev_type = TRANSPORT_EVENT_UNSUBSCRIBE;
      } else if (type == QLINQ_WIRE_KEYFRAME_REQUEST) {
        ev_type = TRANSPORT_EVENT_KEYFRAME_REQUEST;
      }

      transport_event_t ev = {
          .type = ev_type, .conn = conn, .track_id = parsed_track};
      t->callback(t->user_data, &ev);
      quicly_streambuf_ingress_shift(stream, frame.consumed);
    } else if (type == QLINQ_WIRE_UNICAST) {
      size_t payload_size = input.len;
      if (payload_size > TRANSPORT_MAX_RELIABLE_OBJECT_SIZE) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_RESOURCE_LIMIT,
                     "protocol error: payload too large");
        break;
      }

      if (!conn->authenticated) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_AUTHENTICATION,
                     "unauthorized");
        break;
      }

      transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT,
                              .conn = conn,
                              .track_id = {.type = MOQ_TRACK_INPUT},
                              .object = {.track_id = {.type = MOQ_TRACK_INPUT},
                                         .group_id = 0,
                                         .object_id = 0,
                                         .data = input.base,
                                         .size = payload_size,
                                         .is_keyframe = false}};
      t->callback(t->user_data, &ev);
      quicly_streambuf_ingress_shift(stream, frame.consumed);
    } else if (type == QLINQ_WIRE_AUTH_REQUEST) {
      size_t token_len = input.len;
      if (token_len > UINT16_MAX) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_RESOURCE_LIMIT,
                     "protocol error: auth token too large");
        break;
      }

      if (!t->is_server) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: unexpected auth request");
        break;
      }

      transport_event_t ev = {.type = TRANSPORT_EVENT_AUTH,
                              .conn = conn,
                              .auth = {.token = input.base,
                                       .token_len = token_len,
                                       .success = false}};
      t->callback(t->user_data, &ev);
      quicly_streambuf_ingress_shift(stream, frame.consumed);
    } else if (type == QLINQ_WIRE_AUTH_RESPONSE) {
      if (input.len != 1 || input.base[0] > 1) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: invalid auth response");
        break;
      }

      if (t->is_server) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: unexpected auth response");
        break;
      }

      uint8_t status = input.base[0];
      if (status == 1) {
        conn->authenticated = true;
      }
      transport_event_t ev = {
          .type = TRANSPORT_EVENT_AUTH_COMPLETE,
          .conn = conn,
          .auth = {.token = NULL, .token_len = 0, .success = (status == 1)}};
      t->callback(t->user_data, &ev);
      quicly_streambuf_ingress_shift(stream, frame.consumed);
    } else if (type == QLINQ_WIRE_TRACK_OBJECT) {
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                   "protocol error: track object on control stream");
      break;
    } else if (type == QLINQ_WIRE_NACK) {
      qlinq_wire_nack_t nack;
      if (qlinq_wire_decode_nack(input.base, input.len, &nack) !=
          QLINQ_WIRE_OK) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: invalid nack");
        break;
      }

      if (!conn->authenticated) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_AUTHENTICATION,
                     "unauthorized");
        break;
      }

      if (repair_request_allowed(conn, &nack)) {
        moq_track_id_t resolved_track;
        if (transport_subscriptions_find_by_alias(
                &conn->subscriptions, nack.alias, &resolved_track) == 0) {
          sent_object_cache_t *cached = transport_sent_cache_find(
              &t->sent_cache, &resolved_track, nack.group_id, nack.object_id);
          if (cached) {
            uint16_t missing[TRANSPORT_REPAIR_MAX_SYMBOLS];
            size_t missing_count = nack.missing_count;
            if (missing_count > TRANSPORT_REPAIR_MAX_SYMBOLS)
              missing_count = TRANSPORT_REPAIR_MAX_SYMBOLS;
            bool indices_valid = true;
            for (size_t i = 0; i < missing_count; i++) {
              if (!qlinq_wire_nack_index(&nack, i, &missing[i]) ||
                  missing[i] >= FEC_MAX_TOTAL_SYMBOLS) {
                indices_valid = false;
                break;
              }
            }

            bool whole_object =
                (nack.flags & QLINQ_WIRE_NACK_WHOLE_OBJECT) != 0;
            transport_repair_batch_t repair;
            if (indices_valid &&
                transport_repair_build(&t->fec_cache, cached, whole_object,
                                       missing, missing_count, &repair)) {
              for (size_t i = 0; i < repair.count; i++) {
                uint8_t
                    packet[QLINQ_WIRE_FEC_HEADER_SIZE + FEC_MAX_SYMBOL_SIZE];
                size_t packet_len =
                    QLINQ_WIRE_FEC_HEADER_SIZE + repair.symbol_size;
                qlinq_wire_fec_header_t header = {
                    .alias = nack.alias,
                    .is_keyframe = cached->is_keyframe,
                    .priority = cached->priority,
                    .path_id = 0,
                    .group_id = cached->group_id,
                    .object_id = cached->object_id,
                    .symbol_index = repair.indices[i],
                    .total_symbols = repair.total_symbols,
                    .data_symbols = cached->data_symbols,
                    .symbol_size = repair.symbol_size,
                    .original_size = (uint32_t)cached->size,
                    .send_time_ns = get_time_ns()};
                if (qlinq_wire_encode_fec_header(packet, sizeof(packet),
                                                 &header) != QLINQ_WIRE_OK)
                  break;
                memcpy(packet + QLINQ_WIRE_FEC_HEADER_SIZE,
                       repair.symbols + i * repair.symbol_size,
                       repair.symbol_size);
                ptls_iovec_t datagram = ptls_iovec_init(packet, packet_len);
                if (!queue_datagram(conn, 0, datagram))
                  break;
              }
              transport_repair_batch_destroy(&repair);
            }
          }
        }
      }
      quicly_streambuf_ingress_shift(stream, frame.consumed);
    } else {
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                   "protocol error: unexpected frame");
      break;
    }
  }
}

typedef struct {
  quicly_streambuf_t streambuf;
  bool is_control;
  bool alias_bound;
  uint8_t alias;
} stream_ctx_t;

static void on_stream_destroy(quicly_stream_t *stream, quicly_error_t err) {
  transport_conn_t *conn = *quicly_get_data(stream->conn);
  if (conn)
    transport_subscriptions_clear_stream(&conn->subscriptions, stream);
  quicly_streambuf_destroy(stream, err);
}

static void parse_track_stream_messages(transport_t *t, transport_conn_t *conn,
                                        quicly_stream_t *stream) {
  stream_ctx_t *ctx = (stream_ctx_t *)stream->data;
  while (1) {
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    if (input.len == 0)
      break;

    qlinq_wire_frame_t frame;
    qlinq_wire_result_t result = qlinq_wire_decode_frame(
        input.base, input.len, TRANSPORT_WIRE_MAX_STREAM_PAYLOAD, &frame);
    if (result == QLINQ_WIRE_NEED_MORE)
      break;
    if (result != QLINQ_WIRE_OK) {
      close_wire_error(conn, result);
      break;
    }
    if (frame.type != QLINQ_WIRE_TRACK_OBJECT ||
        frame.payload_len < QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE) {
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                   "protocol error: unexpected track frame");
      break;
    }

    if (!conn->authenticated) {
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_AUTHENTICATION,
                   "unauthorized");
      break;
    }

    qlinq_wire_track_object_t wire_object;
    const uint8_t *object_payload = NULL;
    size_t payload_size = 0;
    if (qlinq_wire_decode_track_object(frame.payload, frame.payload_len,
                                       &wire_object, &object_payload,
                                       &payload_size) != QLINQ_WIRE_OK) {
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                   "protocol error: invalid track object");
      break;
    }
    uint8_t alias = wire_object.alias;
    if (ctx->alias_bound && ctx->alias != alias) {
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                   "protocol error: track alias changed");
      break;
    }
    if (!ctx->alias_bound) {
      ctx->alias = alias;
      ctx->alias_bound = true;
      if (transport_subscriptions_bind_stream(&conn->subscriptions, alias,
                                              stream))
        quicly_debug_printf(conn->quic,
                            "Mapped incoming QUIC Stream %" PRIu64
                            " to MoQ track alias %d",
                            stream->stream_id, alias);
    }

    moq_track_id_t resolved_track = {0};
    if (transport_subscriptions_find_by_alias(&conn->subscriptions, alias,
                                              &resolved_track) == 0) {
      transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT,
                              .conn = conn,
                              .track_id = resolved_track,
                              .object = {.track_id = resolved_track,
                                         .group_id = wire_object.group_id,
                                         .object_id = wire_object.object_id,
                                         .data = object_payload,
                                         .size = payload_size,
                                         .is_keyframe = wire_object.is_keyframe,
                                         .priority = wire_object.priority}};
      t->callback(t->user_data, &ev);
    }

    quicly_streambuf_ingress_shift(stream, frame.consumed);
  }
}

/* control stream receive callbacks */
static void on_receive(quicly_stream_t *stream, size_t off, const void *src,
                       size_t len) {
  if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
    return;

  transport_conn_t *conn = *quicly_get_data(stream->conn);
  if (conn) {
    stream_ctx_t *ctx = (stream_ctx_t *)stream->data;
    if (ctx->is_control) {
      parse_control_messages(conn->transport, conn, stream);
    } else {
      parse_track_stream_messages(conn->transport, conn, stream);
    }
  }
}

static void on_stop_sending(quicly_stream_t *stream, quicly_error_t err) {
  stream_ctx_t *ctx = (stream_ctx_t *)stream->data;
  if (ctx && ctx->is_control) {
    quicly_close(stream->conn, 0, "");
  } else {
    quicly_reset_stream(stream, err);
  }
}

static void on_receive_reset(quicly_stream_t *stream, quicly_error_t err) {
  stream_ctx_t *ctx = (stream_ctx_t *)stream->data;
  if (ctx && ctx->is_control) {
    quicly_close(stream->conn, 0, "");
  } else {
    quicly_reset_stream(stream, err);
  }
}

static quicly_error_t on_stream_open(quicly_stream_open_t *self,
                                     quicly_stream_t *stream) {
  (void)self;
  static const quicly_stream_callbacks_t stream_callbacks = {
      on_stream_destroy,
      quicly_streambuf_egress_shift,
      quicly_streambuf_egress_emit,
      on_stop_sending,
      on_receive,
      on_receive_reset};
  int ret;

  if ((ret = quicly_streambuf_create(stream, sizeof(stream_ctx_t))) != 0)
    return ret;
  stream->callbacks = &stream_callbacks;

  stream_ctx_t *ctx = (stream_ctx_t *)stream->data;
  ctx->is_control = (stream->stream_id == 0);
  ctx->alias_bound = false;

  /* client saves the stream pointer */
  transport_conn_t *conn = *quicly_get_data(stream->conn);
  if (conn && ctx->is_control) {
    conn->stream = stream;
  }

  return 0;
}

/* handle incoming datagram frames */
static void send_nack(transport_conn_t *conn, uint8_t alias, uint64_t group_id,
                      uint64_t object_id, const uint16_t *missing,
                      uint16_t count, bool whole_object) {
  if (!conn || !conn->stream ||
      !quicly_sendstate_is_open(&conn->stream->sendstate))
    return;

  if (count > QLINQ_WIRE_MAX_NACK_SYMBOLS)
    return;
  size_t payload_len = 20U + (size_t)count * 2U;
  uint8_t static_buf[1024];
  uint8_t *buf = static_buf;
  if (payload_len > sizeof(static_buf)) {
    buf = malloc(payload_len);
    if (!buf)
      return;
  }

  size_t written = 0;
  uint8_t flags = whole_object ? QLINQ_WIRE_NACK_WHOLE_OBJECT : 0;
  if (qlinq_wire_encode_nack(buf, payload_len, alias, flags, group_id,
                             object_id, missing, count,
                             &written) == QLINQ_WIRE_OK)
    (void)transport_stream_write_frame(conn->stream, QLINQ_WIRE_NACK, buf,
                                       written);

  if (buf != static_buf) {
    free(buf);
  }
}

static void on_receive_datagram_frame(quicly_receive_datagram_frame_t *self,
                                      quicly_conn_t *conn,
                                      ptls_iovec_t payload) {
  (void)self;
  transport_conn_t *tconn = *quicly_get_data(conn);
  if (!tconn)
    return;

  transport_t *t = tconn->transport;
  if (!tconn->authenticated)
    return;

  uint8_t datagram_type;
  qlinq_wire_result_t wire_result = qlinq_wire_decode_datagram_type(
      payload.base, payload.len, &datagram_type);
  if (wire_result != QLINQ_WIRE_OK)
    return;

  if (datagram_type == QLINQ_WIRE_DATAGRAM_TELEMETRY) {
    qlinq_wire_telemetry_t telemetry;
    if (qlinq_wire_decode_telemetry(payload.base, payload.len, &telemetry) !=
        QLINQ_WIRE_OK)
      return;
    uint8_t pid = telemetry.path_id;
    if (pid < TRANSPORT_MAX_PATHS) {
      uint64_t s_ns = telemetry.send_time_ns;
      uint64_t r_ns = telemetry.recv_time_ns;

      /* relative owd (queuing delay estimation) */
      int64_t current_owd = (int64_t)r_ns - (int64_t)s_ns;
      if (tconn->min_owd_ns[pid] == 0 || current_owd < tconn->min_owd_ns[pid]) {
        tconn->min_owd_ns[pid] = current_owd;
      }
      int64_t relative_owd_ns = current_owd - tconn->min_owd_ns[pid];
      uint32_t relative_owd_us = relative_owd_ns / 1000;
      tconn->latest_owd_fp[pid] =
          FP_FROM_INT(relative_owd_us) / 1000000; /* convert us to seconds */

      tconn->last_telemetry_s_ns[pid] = s_ns;
      tconn->last_telemetry_r_ns[pid] = r_ns;
    }
    return;
  }

  qlinq_wire_fec_header_t hdr;
  if (qlinq_wire_decode_fec_header(payload.base, payload.len, &hdr) !=
      QLINQ_WIRE_OK)
    return;

  uint8_t track_id = hdr.alias;
  moq_track_id_t resolved_track;
  if (transport_subscriptions_find_by_alias(&tconn->subscriptions, track_id,
                                            &resolved_track) != 0) {
    return;
  }

  /* automatically send a telemetry reply to measure OWD */
  uint8_t reply[QLINQ_WIRE_TELEMETRY_SIZE];
  qlinq_wire_telemetry_t telemetry = {.path_id = hdr.path_id,
                                      .send_time_ns = hdr.send_time_ns,
                                      .recv_time_ns = get_time_ns()};
  if (qlinq_wire_encode_telemetry(reply, sizeof(reply), &telemetry) ==
      QLINQ_WIRE_OK) {
    ptls_iovec_t reply_vec = ptls_iovec_init(reply, sizeof(reply));
    (void)queue_datagram(tconn, hdr.path_id, reply_vec);
  }

  uint8_t is_keyframe = hdr.is_keyframe;
  uint64_t group_id = hdr.group_id;
  uint64_t object_id = hdr.object_id;
  uint16_t symbol_index = hdr.symbol_index;
  uint16_t total_symbols = hdr.total_symbols;
  uint16_t data_symbols = hdr.data_symbols;
  uint16_t symbol_size = hdr.symbol_size;
  uint32_t original_size = hdr.original_size;

  if (total_symbols == 0 || total_symbols > FEC_MAX_TOTAL_SYMBOLS ||
      symbol_size == 0 || symbol_size > FEC_MAX_SYMBOL_SIZE ||
      data_symbols == 0 || data_symbols > total_symbols ||
      symbol_index >= total_symbols)
    return;

  if (original_size > FEC_MAX_OBJECT_SIZE ||
      original_size > (uint32_t)data_symbols * symbol_size ||
      original_size == 0)
    return;

  if (payload.len != QLINQ_WIRE_FEC_HEADER_SIZE + symbol_size)
    return;

  if (resolved_track.type == MOQ_TRACK_DATA &&
      (resolved_track.flags & MOQ_TRACK_FLAG_FEC_RATELESS)) {
    object_gap_state_t *gap = &tconn->object_gaps[track_id];
    if (object_id > gap->last_seen) {
      if (gap->last_seen > 0 && object_id - gap->last_seen > 1) {
        uint64_t first_missing = gap->last_seen + 1;
        uint64_t missing_count = object_id - first_missing;
        if (missing_count <= 32) {
          if (gap->pending_mask == 0) {
            gap->pending_base = first_missing;
            gap->detected_at_ms = transport_get_time_ms();
            gap->group_id = group_id;
          }
          if (first_missing >= gap->pending_base &&
              first_missing - gap->pending_base < 32) {
            uint32_t offset = (uint32_t)(first_missing - gap->pending_base);
            uint32_t available = 32 - offset;
            uint32_t count =
                missing_count < available ? missing_count : available;
            uint32_t bits = count == 32 ? UINT32_MAX : ((1U << count) - 1U);
            gap->pending_mask |= bits << offset;
          }
        }
      }
      gap->last_seen = object_id;
    } else if (gap->pending_mask != 0 && object_id >= gap->pending_base &&
               object_id - gap->pending_base < 32) {
      gap->pending_mask &= ~(1U << (object_id - gap->pending_base));
    }
  }

  /* lookup active frame assembler cache */
  frame_assembler_t *asm_slot = NULL;
  for (size_t i = 0; i < ASSEMBLER_CACHE_SIZE; i++) {
    frame_assembler_t *a = &tconn->assemblers[i];
    if (a->total_symbols > 0 && a->track_id == track_id &&
        a->group_id == group_id && a->object_id == object_id) {
      if (a->symbol_size != symbol_size || a->data_symbols != data_symbols ||
          a->original_size != original_size) {
        return; /* malformed or malicious packet */
      }
      asm_slot = a;
      break;
    }
  }

  if (!asm_slot) {
    asm_slot = &tconn->assemblers[tconn->assembler_index];
    tconn->assembler_index =
        (tconn->assembler_index + 1) % ASSEMBLER_CACHE_SIZE;

    if (asm_slot->total_symbols > 0 && !asm_slot->decoded) {
      moq_track_id_t resolved_track;
      if (transport_subscriptions_find_by_alias(&tconn->subscriptions,
                                                asm_slot->track_id,
                                                &resolved_track) == 0) {
        transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT_LOST,
                                .conn = tconn,
                                .track_id = resolved_track,
                                .object = {.track_id = resolved_track,
                                           .group_id = asm_slot->group_id,
                                           .object_id = asm_slot->object_id}};
        tconn->transport->callback(tconn->transport->user_data, &ev);
      }
    }

    if (!asm_slot->buffers || asm_slot->capacity_symbols < total_symbols ||
        asm_slot->capacity_symbol_size < symbol_size) {
      release_assembler(t, asm_slot);
      if (!grow_assembler(t, asm_slot, total_symbols, symbol_size)) {
        release_assembler(t, asm_slot);
        return;
      }
    }

    memset(asm_slot->received_mask, 0,
           asm_slot->capacity_symbols * sizeof(bool));
    asm_slot->track_id = track_id;
    asm_slot->group_id = group_id;
    asm_slot->object_id = object_id;
    asm_slot->total_symbols = total_symbols;
    asm_slot->data_symbols = data_symbols;
    asm_slot->symbol_size = symbol_size;
    asm_slot->original_size = original_size;
    asm_slot->priority = hdr.priority;
    asm_slot->decoded = false;
    asm_slot->received_count = 0;
    asm_slot->nack_sent = false;
    asm_slot->first_symbol_time_ms = transport_get_time_ms();
    asm_slot->last_activity_time_ms = asm_slot->first_symbol_time_ms;
  }

  if (asm_slot->decoded)
    return;

  if (total_symbols > asm_slot->total_symbols) {
    if (!grow_assembler(t, asm_slot, total_symbols, symbol_size)) {
      return;
    }
    asm_slot->total_symbols = total_symbols;
  }

  total_symbols = asm_slot->total_symbols;
  data_symbols = asm_slot->data_symbols;
  symbol_size = asm_slot->symbol_size;
  original_size = asm_slot->original_size;

  if (symbol_index >= asm_slot->total_symbols)
    return;

  if (!asm_slot->received_mask[symbol_index]) {
    memcpy(asm_slot->buffers[symbol_index],
           payload.base + QLINQ_WIRE_FEC_HEADER_SIZE, symbol_size);
    asm_slot->received_mask[symbol_index] = true;
    asm_slot->received_count++;
    asm_slot->last_activity_time_ms = transport_get_time_ms();
  }

  if (asm_slot->received_count >= data_symbols) {
    bool got_all_data = true;
    for (size_t i = 0; i < data_symbols; i++) {
      if (!asm_slot->received_mask[i]) {
        got_all_data = false;
        break;
      }
    }

    bool success = false;
    if (got_all_data) {
      success = true;
    } else {
      size_t parity_symbols = total_symbols - data_symbols;
      if (parity_symbols > 0) {
        fec_type_t fec_type =
            total_symbols > 255 ? FEC_RAPTORQ : FEC_REED_SOLOMON;
        fec_t *fec = transport_fec_cache_get(
            &t->fec_cache, fec_type, data_symbols, parity_symbols, symbol_size);
        if (fec) {
          for (size_t i = 0; i < total_symbols; i++) {
            asm_slot->missing_mask[i] = !asm_slot->received_mask[i];
          }
          success = fec_decode(fec, asm_slot->buffers, asm_slot->missing_mask);
        }
      }
    }

    if (success) {
      uint8_t *full_data = malloc(original_size);
      if (!full_data)
        return; /* out of memory */
      size_t bytes_left = original_size;
      for (size_t i = 0; i < data_symbols; i++) {
        size_t chunk = (bytes_left < symbol_size) ? bytes_left : symbol_size;
        if (chunk > 0) {
          memcpy(full_data + (i * symbol_size), asm_slot->buffers[i], chunk);
          bytes_left -= chunk;
        }
      }

      resolved_track.flags |= MOQ_TRACK_FLAG_FEC_ENABLED;
      resolved_track.flags &= ~MOQ_TRACK_FLAG_RELIABLE;
      transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT,
                              .conn = tconn,
                              .track_id = resolved_track,
                              .object = {.track_id = resolved_track,
                                         .group_id = group_id,
                                         .object_id = object_id,
                                         .data = full_data,
                                         .size = original_size,
                                         .is_keyframe = (is_keyframe != 0),
                                         .priority = asm_slot->priority}};
      t->callback(t->user_data, &ev);
      free(full_data);
      release_assembler(t, asm_slot);
    }
  }
}

typedef struct {
  uint32_t index;
  struct sockaddr_storage addr;
  socklen_t addr_len;
  int is_added;
} ifmon_pipe_msg_t;

static void bind_to_device(int fd, uint32_t index) {
  if (index == 0)
    return;
#if defined(__linux__)
  char ifname[IF_NAMESIZE];
  if (if_indextoname(index, ifname)) {
    if (strncmp(ifname, "veth", 4) == 0)
      return;
    setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
  }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
#ifndef IP_BOUND_IF
#define IP_BOUND_IF 25
#endif
#ifndef IPV6_BOUND_IF
#define IPV6_BOUND_IF 125
#endif
  unsigned int idx = index;
  setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx));
  setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, sizeof(idx));
#elif defined(_WIN32)
  DWORD idx = index;
  setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, (const char *)&idx, sizeof(idx));
  setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_IF, (const char *)&idx,
             sizeof(idx));
#endif
}

static void on_ifmon_update(const ifmon_update_t *update, void *userdata) {
  transport_t *t = userdata;

  if (update->is_initial) {
    /* For now, ignore initial snapshot since we bind via config->bind_hosts */
    return;
  }

  for (int i = 0; i < update->added_count; i++) {
    uint32_t idx = update->added[i];
    for (int j = 0; j < update->interfaces->count; j++) {
      if (update->interfaces->ifaces[j].index == idx) {
        const ifmon_iface_t *iface = &update->interfaces->ifaces[j];
        for (int k = 0; k < iface->addr_count; k++) {
          const ifmon_addr_t *a = &iface->addrs[k];
          ifmon_pipe_msg_t msg = {0};
          msg.index = idx;
          msg.is_added = 1;
          if (a->family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&msg.addr;
            sin->sin_family = AF_INET;
            sin->sin_addr = a->ip.v4;
            msg.addr_len = sizeof(*sin);
          } else {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&msg.addr;
            sin6->sin6_family = AF_INET6;
            sin6->sin6_addr = a->ip.v6;
            msg.addr_len = sizeof(*sin6);
          }
          ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
          (void)w;
        }
        break;
      }
    }
  }

  for (int i = 0; i < update->removed_count; i++) {
    ifmon_pipe_msg_t msg = {0};
    msg.index = update->removed[i];
    msg.is_added = 0;
    msg.addr.ss_family = AF_UNSPEC;
    ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
    (void)w;
  }

  for (int i = 0; i < update->modified_count; i++) {
    const ifmon_iface_diff_t *diff = &update->modified[i];

    if (diff->link_state_changed) {
      for (int k = 0; k < update->interfaces->count; k++) {
        const ifmon_iface_t *iface = &update->interfaces->ifaces[k];
        if (iface->index == diff->index) {
          for (int a_idx = 0; a_idx < iface->addr_count; a_idx++) {
            const ifmon_addr_t *a = &iface->addrs[a_idx];
            ifmon_pipe_msg_t msg = {0};
            msg.index = diff->index;
            msg.is_added = diff->is_up ? 1 : 0;
            if (a->family == AF_INET) {
              struct sockaddr_in *sin = (struct sockaddr_in *)&msg.addr;
              sin->sin_family = AF_INET;
              sin->sin_addr = a->ip.v4;
              msg.addr_len = sizeof(*sin);
            } else {
              struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&msg.addr;
              sin6->sin6_family = AF_INET6;
              sin6->sin6_addr = a->ip.v6;
              msg.addr_len = sizeof(*sin6);
            }
            ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
            (void)w;
          }
          break;
        }
      }
    }

    for (int j = 0; j < diff->addrs_added_count; j++) {
      const ifmon_addr_t *a = &diff->addrs_added[j];
      ifmon_pipe_msg_t msg = {0};
      msg.index = diff->index;
      msg.is_added = 1;
      if (a->family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&msg.addr;
        sin->sin_family = AF_INET;
        sin->sin_addr = a->ip.v4;
        msg.addr_len = sizeof(*sin);
      } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&msg.addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = a->ip.v6;
        msg.addr_len = sizeof(*sin6);
      }
      ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
      (void)w;
    }

    for (int j = 0; j < diff->addrs_removed_count; j++) {
      const ifmon_addr_t *a = &diff->addrs_removed[j];
      ifmon_pipe_msg_t msg = {0};
      msg.index = diff->index;
      msg.is_added = 0;
      if (a->family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&msg.addr;
        sin->sin_family = AF_INET;
        sin->sin_addr = a->ip.v4;
        msg.addr_len = sizeof(*sin);
      } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&msg.addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = a->ip.v6;
        msg.addr_len = sizeof(*sin6);
      }
      ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
      (void)w;
    }
  }
}

static bool set_fd_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static void configure_socket_buffers(int fd) {
  int buf_size = 2 * 1024 * 1024; /* 2mb buffer size */
  if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) != 0)
    fprintf(stderr, "transport: unable to enlarge send buffer: %s\n",
            strerror(errno));
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) != 0)
    fprintf(stderr, "transport: unable to enlarge receive buffer: %s\n",
            strerror(errno));
}

transport_t *transport_create(const transport_config_t *config) {
  if (!config || !config->callback || config->port == 0 ||
      config->num_bind_hosts == 0 ||
      config->num_bind_hosts > TRANSPORT_MAX_PATHS ||
      config->num_remote_hosts > TRANSPORT_MAX_PATHS ||
      config->simulated_loss_rate > 100 ||
      (!config->verify_peer && !config->allow_insecure_peer)) {
    if (config && config->callback && config->port != 0 &&
        config->num_bind_hosts > 0 &&
        config->num_bind_hosts <= TRANSPORT_MAX_PATHS &&
        config->num_remote_hosts <= TRANSPORT_MAX_PATHS &&
        config->simulated_loss_rate <= 100)
      fprintf(stderr,
              "transport: peer verification requires verify_peer or explicit "
              "allow_insecure_peer\n");
    return NULL;
  }
  for (size_t i = 0; i < config->num_bind_hosts; i++) {
    if (!config->bind_hosts[i])
      return NULL;
  }
  for (size_t i = 0; i < config->num_remote_hosts; i++) {
    if (!config->remote_hosts[i])
      return NULL;
  }

  transport_t *t = calloc(1, sizeof(transport_t));
  if (!t) {
    fprintf(stderr, "transport: failed to allocate transport state\n");
    return NULL;
  }

  for (size_t i = 0; i < TRANSPORT_MAX_PATHS; i++)
    t->fds[i] = -1;
  t->ifmon_pipe[0] = -1;
  t->ifmon_pipe[1] = -1;

  if (!transport_arena_init(&t->arena, 16U * 1024U * 1024U)) {
    fprintf(stderr, "transport: failed to allocate packet arena\n");
    free(t);
    return NULL;
  }

  t->callback = config->callback;
  t->user_data = config->user_data;
  t->is_server = (config->num_remote_hosts == 0);
  t->simulated_loss_rate = config->simulated_loss_rate;

  t->last_pathflow_update = ptls_get_time.cb(&ptls_get_time);

  if (pipe(t->ifmon_pipe) == 0) {
    if (set_fd_nonblocking(t->ifmon_pipe[0]) &&
        set_fd_nonblocking(t->ifmon_pipe[1])) {
      (void)ifmon_watch_start(&t->ifmon_w, on_ifmon_update, t);
    } else {
      CLOSE_SOCKET(t->ifmon_pipe[0]);
      CLOSE_SOCKET(t->ifmon_pipe[1]);
      t->ifmon_pipe[0] = -1;
      t->ifmon_pipe[1] = -1;
    }
  } else {
    t->ifmon_pipe[0] = -1;
    t->ifmon_pipe[1] = -1;
  }

  /* setup cryptographic context */
  t->tls_ctx.random_bytes = ptls_openssl_random_bytes;
  t->tls_ctx.get_time = &ptls_get_time;
  t->tls_ctx.key_exchanges = ptls_openssl_key_exchanges;
  t->tls_ctx.cipher_suites = ptls_openssl_cipher_suites;

  t->stream_open.cb = on_stream_open;
  t->receive_datagram.cb = on_receive_datagram_frame;
  t->verifier_initialized = false;

  t->quic_ctx = quicly_spec_context;

  /* Setup CID encryptor to support active connection migration */
  static char cid_key[16];
  ptls_openssl_random_bytes(cid_key, sizeof(cid_key));
  t->quic_ctx.cid_encryptor = quicly_new_default_cid_encryptor(
      &ptls_openssl_quiclb, &ptls_openssl_aes128ecb, &ptls_openssl_sha256,
      ptls_iovec_init(cid_key, sizeof(cid_key)));

  t->quic_ctx.tls = &t->tls_ctx;
  quicly_amend_ptls_context(t->quic_ctx.tls);
  t->quic_ctx.stream_open = &t->stream_open;
  t->quic_ctx.receive_datagram_frame = &t->receive_datagram;

  t->quic_ctx.path_scheduler = &quicly_round_robin_path_scheduler;

  t->quic_ctx.initcwnd_packets = 100;
  t->quic_ctx.transport_params.max_datagram_frame_size = 1500;
  t->quic_ctx.transport_params.max_streams_uni = 100;
  t->quic_ctx.transport_params.max_streams_bidi = 100;

  t->quic_ctx.transport_params.active_connection_id_limit = 8;
  t->quic_ctx.transport_params.initial_max_path_id = TRANSPORT_MAX_PATHS;

  t->num_fds = config->num_bind_hosts;
  t->num_remote_addrs = config->num_remote_hosts;

  for (size_t i = 0; i < t->num_fds; i++) {
    if (strchr(config->bind_hosts[i], ':')) {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&t->local_addrs[i];
      sin6->sin6_family = AF_INET6;
      if (inet_pton(AF_INET6, config->bind_hosts[i], &sin6->sin6_addr) != 1) {
        fprintf(stderr, "transport: invalid IPv6 bind address: %s\n",
                config->bind_hosts[i]);
        transport_destroy(t);
        return NULL;
      }
      sin6->sin6_port = t->is_server ? htons(config->port) : 0;
      t->local_addrs_len[i] = sizeof(struct sockaddr_in6);
      t->fds[i] = socket(AF_INET6, SOCK_DGRAM, 0);
    } else {
      struct sockaddr_in *sin = (struct sockaddr_in *)&t->local_addrs[i];
      sin->sin_family = AF_INET;
      if (inet_pton(AF_INET, config->bind_hosts[i], &sin->sin_addr) != 1) {
        fprintf(stderr, "transport: invalid IPv4 bind address: %s\n",
                config->bind_hosts[i]);
        transport_destroy(t);
        return NULL;
      }
      sin->sin_port = t->is_server ? htons(config->port) : 0;
      t->local_addrs_len[i] = sizeof(struct sockaddr_in);
      t->fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
    }
    if (t->fds[i] < 0) {
      fprintf(stderr, "transport: socket creation failed: %s\n",
              strerror(errno));
      transport_destroy(t);
      return NULL;
    }

    int reuse = 1;
    if (setsockopt(t->fds[i], SOL_SOCKET, SO_REUSEADDR, &reuse,
                   sizeof(reuse)) != 0)
      fprintf(stderr, "transport: SO_REUSEADDR failed: %s\n", strerror(errno));

    if (bind(t->fds[i], (struct sockaddr *)&t->local_addrs[i],
             t->local_addrs_len[i]) != 0) {
      fprintf(stderr, "transport: bind failed for %s:%u: %s\n",
              config->bind_hosts[i], config->port, strerror(errno));
      transport_destroy(t);
      return NULL;
    }

    configure_socket_buffers(t->fds[i]);

    if (!set_fd_nonblocking(t->fds[i])) {
      fprintf(stderr, "transport: failed to make socket nonblocking: %s\n",
              strerror(errno));
      transport_destroy(t);
      return NULL;
    }
  }

  if (t->is_server || (config->cert_file && config->key_file)) {
    if (transport_tls_load_certificate_and_key(&t->tls_ctx, &t->sign_cert,
                                               config->cert_file,
                                               config->key_file) != 0) {
      transport_destroy(t);
      return NULL;
    }
  }

  if (config->verify_peer) {
    X509_STORE *store = NULL;
    if (config->ca_file) {
      store = X509_STORE_new();
      if (X509_STORE_load_locations(store, config->ca_file, NULL) != 1) {
        fprintf(stderr, "failed to load CA certificates from %s\n",
                config->ca_file);
        X509_STORE_free(store);
        transport_destroy(t);
        return NULL;
      }
    }

    /* ptls_openssl_init_verify_certificate will take its own reference to store
     * (if provided), or load the system default certificates if store is NULL
     */
    if (ptls_openssl_init_verify_certificate(&t->verifier, store) != 0) {
      fprintf(stderr, "failed to initialize certificate verifier\n");
      if (store) {
        X509_STORE_free(store);
      }
      transport_destroy(t);
      return NULL;
    }
    if (store) {
      X509_STORE_free(store); /* drop our local reference */
    }

    t->tls_ctx.verify_certificate = &t->verifier.super;
    t->verifier_initialized = true;

    if (t->is_server) {
      t->tls_ctx.require_client_authentication = 1;
    }
  } else {
    transport_tls_init_insecure_verifier(&t->verifier);
    t->tls_ctx.verify_certificate = &t->verifier.super;
    t->verifier_initialized = false;
  }

  if (!t->is_server) {
    for (size_t i = 0; i < t->num_remote_addrs; i++) {
      if (strchr(config->remote_hosts[i], ':')) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&t->remote_addrs[i];
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(config->port);
        if (inet_pton(AF_INET6, config->remote_hosts[i], &sin6->sin6_addr) !=
            1) {
          transport_destroy(t);
          return NULL;
        }
        t->remote_addrs_len[i] = sizeof(struct sockaddr_in6);
      } else {
        struct sockaddr_in *sin = (struct sockaddr_in *)&t->remote_addrs[i];
        sin->sin_family = AF_INET;
        sin->sin_port = htons(config->port);
        if (inet_pton(AF_INET, config->remote_hosts[i], &sin->sin_addr) != 1) {
          transport_destroy(t);
          return NULL;
        }
        t->remote_addrs_len[i] = sizeof(struct sockaddr_in);
      }
    }

    transport_conn_t *conn = calloc(1, sizeof(transport_conn_t));
    if (!conn) {
      transport_destroy(t);
      return NULL;
    }
    conn->transport = t;

    int ret =
        quicly_connect(&conn->quic, &t->quic_ctx, config->remote_hosts[0],
                       (struct sockaddr *)&t->remote_addrs[0],
                       (struct sockaddr *)&t->local_addrs[0], &t->next_cid,
                       ptls_iovec_init(NULL, 0), NULL, NULL, NULL);
    if (ret != 0) {
      free(conn);
      transport_destroy(t);
      return NULL;
    }

    *quicly_get_data(conn->quic) = conn;
    t->client_conn = conn;

    if (quicly_open_stream(conn->quic, &conn->stream, 0) != 0 ||
        !conn->stream) {
      transport_destroy(t);
      return NULL;
    }
  }

  /* make socket nonblocking is handled in the loop */
  return t;
}

void transport_destroy(transport_t *t) {
  if (!t)
    return;

  if (t->ifmon_pipe[0] >= 0) {
    ifmon_watch_stop(&t->ifmon_w);
  }
  if (t->ifmon_pipe[0] >= 0) {
    CLOSE_SOCKET(t->ifmon_pipe[0]);
    CLOSE_SOCKET(t->ifmon_pipe[1]);
  }

  for (size_t i = 0; i < t->num_fds; i++) {
    if (t->fds[i] >= 0) {
      CLOSE_SOCKET(t->fds[i]);
    }
  }

  if (t->is_server) {
    for (size_t i = 0; i < t->conn_count; i++) {
      transport_conn_t *conn = t->conns[i];
      quicly_free(conn->quic);
      for (size_t a = 0; a < ASSEMBLER_CACHE_SIZE; a++)
        release_assembler(t, &conn->assemblers[a]);
      free(conn);
    }
  } else if (t->client_conn) {
    transport_conn_t *conn = t->client_conn;
    quicly_free(conn->quic);
    for (size_t a = 0; a < ASSEMBLER_CACHE_SIZE; a++)
      release_assembler(t, &conn->assemblers[a]);
    free(conn);
  }

  transport_sent_cache_destroy(&t->sent_cache);
  transport_fec_cache_destroy(&t->fec_cache);

  transport_arena_destroy(&t->arena);

  if (t->quic_ctx.cid_encryptor != NULL) {
    quicly_free_default_cid_encryptor(t->quic_ctx.cid_encryptor);
  }

  if (t->fec_buf) {
    free(t->fec_buf);
  }

  if (t->verifier_initialized) {
    ptls_openssl_dispose_verify_certificate(&t->verifier);
  }

  if (t->tls_ctx.sign_certificate) {
    ptls_openssl_dispose_sign_certificate(&t->sign_cert);
  }
  for (size_t i = 0; i < t->tls_ctx.certificates.count; i++)
    free(t->tls_ctx.certificates.list[i].base);
  free(t->tls_ctx.certificates.list);

  free(t);
}

static bool flush_fec_buffer(transport_t *t);

void transport_tick(transport_t *t) {
  if (!t)
    return;

  /* Sweep active assemblers for 10ms NACK retries */
  int64_t now_nack_ms = transport_get_time_ms();
  size_t object_nack_budget = 32;
  size_t active_conns = t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
  for (size_t c = 0; c < active_conns; c++) {
    transport_conn_t *conn = t->is_server ? t->conns[c] : t->client_conn;
    if (!conn || !conn->quic ||
        quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING)
      continue;

    for (size_t alias = 0; alias <= UINT8_MAX && object_nack_budget > 0;
         alias++) {
      object_gap_state_t *gap = &conn->object_gaps[alias];
      if (gap->pending_mask == 0 ||
          now_nack_ms - gap->detected_at_ms < FEC_NACK_DELAY_MS)
        continue;
      for (uint32_t bit = 0; bit < 32 && object_nack_budget > 0; bit++) {
        if ((gap->pending_mask & (1U << bit)) == 0)
          continue;
        send_nack(conn, (uint8_t)alias, gap->group_id, gap->pending_base + bit,
                  NULL, 0, true);
        gap->pending_mask &= ~(1U << bit);
        object_nack_budget--;
      }
    }

    for (size_t i = 0; i < ASSEMBLER_CACHE_SIZE; i++) {
      frame_assembler_t *asm_slot = &conn->assemblers[i];
      if (asm_slot->total_symbols == 0)
        continue;

      if (now_nack_ms - asm_slot->last_activity_time_ms >=
          FEC_ASSEMBLER_TIMEOUT_MS) {
        moq_track_id_t resolved_track;
        if (transport_subscriptions_find_by_alias(&conn->subscriptions,
                                                  asm_slot->track_id,
                                                  &resolved_track) == 0) {
          transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT_LOST,
                                  .conn = conn,
                                  .track_id = resolved_track,
                                  .object = {.track_id = resolved_track,
                                             .group_id = asm_slot->group_id,
                                             .object_id = asm_slot->object_id}};
          t->callback(t->user_data, &ev);
        }
        release_assembler(t, asm_slot);
        continue;
      }

      if (!asm_slot->decoded &&
          now_nack_ms - asm_slot->first_symbol_time_ms >= FEC_NACK_DELAY_MS &&
          (!asm_slot->nack_sent ||
           now_nack_ms - asm_slot->last_nack_time_ms >= FEC_NACK_DELAY_MS)) {
        moq_track_id_t resolved_track;
        if (transport_subscriptions_find_by_alias(&conn->subscriptions,
                                                  asm_slot->track_id,
                                                  &resolved_track) == 0) {
          if (!(resolved_track.flags & MOQ_TRACK_FLAG_FEC_RATELESS))
            continue; /* Fixed RS-FEC does not send NACKs */
        }
        uint16_t missing_count = 0;
        for (uint16_t s = 0; s < asm_slot->total_symbols; s++) {
          if (!asm_slot->received_mask[s] &&
              missing_count < TRANSPORT_REPAIR_MAX_SYMBOLS) {
            asm_slot->missing_indices[missing_count++] = s;
          }
        }
        if (missing_count > 0) {
          send_nack(conn, asm_slot->track_id, asm_slot->group_id,
                    asm_slot->object_id, asm_slot->missing_indices,
                    missing_count, false);
          asm_slot->nack_sent = true;
          asm_slot->last_nack_time_ms = now_nack_ms;
        }
      }
    }
  }

  /* Check for FEC grouping buffer timeout (3 milliseconds) */
  if (t->fec_buf_len > 0) {
    uint64_t now = ptls_get_time.cb(&ptls_get_time);
    if ((now - t->fec_first_pkt_time) >= 3) {
      (void)flush_fec_buffer(t);
    }
  }

  /* process ifmon events */
  if (t->ifmon_pipe[0] >= 0) {
    ifmon_pipe_msg_t msg;
    while (read(t->ifmon_pipe[0], &msg, sizeof(msg)) == sizeof(msg)) {
      if (msg.is_added) {
        if (t->num_fds < TRANSPORT_MAX_PATHS) {
          /* Deduplicate: Check if this IP is already bound */
          int is_duplicate = 0;
          for (size_t i = 0; i < t->num_fds; i++) {
            if (t->local_addrs[i].ss_family == msg.addr.ss_family) {
              if (msg.addr.ss_family == AF_INET) {
                struct sockaddr_in *s1 =
                    (struct sockaddr_in *)&t->local_addrs[i];
                struct sockaddr_in *s2 = (struct sockaddr_in *)&msg.addr;
                if (s1->sin_addr.s_addr == s2->sin_addr.s_addr)
                  is_duplicate = 1;
              } else if (msg.addr.ss_family == AF_INET6) {
                struct sockaddr_in6 *s1 =
                    (struct sockaddr_in6 *)&t->local_addrs[i];
                struct sockaddr_in6 *s2 = (struct sockaddr_in6 *)&msg.addr;
                if (memcmp(&s1->sin6_addr, &s2->sin6_addr,
                           sizeof(struct in6_addr)) == 0)
                  is_duplicate = 1;
              }
            }
          }
          if (is_duplicate) {
            continue;
          }

          /* Check if the new IP address matches the client/server side of the
           * initially bound IP address */
          if (msg.addr.ss_family == AF_INET &&
              t->local_addrs[0].ss_family == AF_INET) {
            uint32_t bound_ip = ntohl(
                ((struct sockaddr_in *)&t->local_addrs[0])->sin_addr.s_addr);
            uint32_t new_ip =
                ntohl(((struct sockaddr_in *)&msg.addr)->sin_addr.s_addr);
            if ((bound_ip & 0xFF) != (new_ip & 0xFF)) {
              continue;
            }
          }
          int fd = socket(msg.addr.ss_family, SOCK_DGRAM, 0);
          if (fd >= 0) {
            int reuse = 1;
            if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse,
                           sizeof(reuse)) != 0)
              fprintf(stderr, "ifmon: SO_REUSEADDR failed: %s\n",
                      strerror(errno));
            configure_socket_buffers(fd);
            if (msg.addr.ss_family == AF_INET) {
              ((struct sockaddr_in *)&msg.addr)->sin_port =
                  t->is_server
                      ? (t->local_addrs[0].ss_family == AF_INET
                             ? ((struct sockaddr_in *)&t->local_addrs[0])
                                   ->sin_port
                             : ((struct sockaddr_in6 *)&t->local_addrs[0])
                                   ->sin6_port)
                      : 0;
            } else {
              ((struct sockaddr_in6 *)&msg.addr)->sin6_port =
                  t->is_server
                      ? (t->local_addrs[0].ss_family == AF_INET
                             ? ((struct sockaddr_in *)&t->local_addrs[0])
                                   ->sin_port
                             : ((struct sockaddr_in6 *)&t->local_addrs[0])
                                   ->sin6_port)
                      : 0;
            }

            if (bind(fd, (struct sockaddr *)&msg.addr, msg.addr_len) == 0) {
              if (!set_fd_nonblocking(fd)) {
                CLOSE_SOCKET(fd);
                continue;
              }
              bind_to_device(fd, msg.index);

              t->fds[t->num_fds] = fd;
              t->local_addrs[t->num_fds] = msg.addr;
              t->local_addrs_len[t->num_fds] = msg.addr_len;
              t->local_ifindices[t->num_fds] = msg.index;
              t->num_fds++;

              char ip_str[64];
              if (msg.addr.ss_family == AF_INET) {
                inet_ntop(AF_INET, &((struct sockaddr_in *)&msg.addr)->sin_addr,
                          ip_str, sizeof(ip_str));
              } else {
                inet_ntop(AF_INET6,
                          &((struct sockaddr_in6 *)&msg.addr)->sin6_addr,
                          ip_str, sizeof(ip_str));
              }
              fprintf(stderr, "ifmon: opened new socket for local IP %s\n",
                      ip_str);

              if (!t->is_server && t->client_conn) {
                for (size_t r = 0; r < t->num_remote_addrs; r++) {
                  /* Only open path if the local and remote addresses are on the
                   * same /24 subnet */
                  if (t->remote_addrs[r].ss_family == AF_INET &&
                      msg.addr.ss_family == AF_INET) {
                    uint32_t remote_ip =
                        ntohl(((struct sockaddr_in *)&t->remote_addrs[r])
                                  ->sin_addr.s_addr);
                    uint32_t local_ip = ntohl(
                        ((struct sockaddr_in *)&msg.addr)->sin_addr.s_addr);
                    if ((remote_ip & 0xFFFFFF00) != (local_ip & 0xFFFFFF00)) {
                      continue;
                    }
                  }
                  quicly_open_path(t->client_conn->quic,
                                   (struct sockaddr *)&t->remote_addrs[r],
                                   (struct sockaddr *)&msg.addr);
                }
              }
            } else {
              CLOSE_SOCKET(fd);
            }
          }
        }
      } else {
        /* ip removed */
        for (size_t i = 0; i < t->num_fds; i++) {
          int match = msg.addr.ss_family == AF_UNSPEC
                          ? t->local_ifindices[i] == msg.index
                          : 0;
          if (!match && t->local_addrs[i].ss_family == msg.addr.ss_family) {
            if (msg.addr.ss_family == AF_INET) {
              struct sockaddr_in *s1 = (struct sockaddr_in *)&t->local_addrs[i];
              struct sockaddr_in *s2 = (struct sockaddr_in *)&msg.addr;
              if (s1->sin_addr.s_addr == s2->sin_addr.s_addr)
                match = 1;
            } else {
              struct sockaddr_in6 *s1 =
                  (struct sockaddr_in6 *)&t->local_addrs[i];
              struct sockaddr_in6 *s2 = (struct sockaddr_in6 *)&msg.addr;
              if (memcmp(&s1->sin6_addr, &s2->sin6_addr,
                         sizeof(struct in6_addr)) == 0)
                match = 1;
            }
          }
          if (match) {
            CLOSE_SOCKET(t->fds[i]);
            /* remove from array */
            for (size_t j = i; j < t->num_fds - 1; j++) {
              t->fds[j] = t->fds[j + 1];
              t->local_addrs[j] = t->local_addrs[j + 1];
              t->local_addrs_len[j] = t->local_addrs_len[j + 1];
              t->local_ifindices[j] = t->local_ifindices[j + 1];
            }
            t->num_fds--;
            fprintf(stderr, "ifmon: removed socket for local IP\n");
            break;
          }
        }
      }
    }
  }

  for (size_t fd_idx = 0; fd_idx < t->num_fds; fd_idx++) {
    while (1) {
      uint8_t buf[2048];
      struct sockaddr_storage sa;
      socklen_t sa_len = sizeof(sa);
      ssize_t rret = recvfrom(t->fds[fd_idx], buf, sizeof(buf), 0,
                              (struct sockaddr *)&sa, &sa_len);
      if (rret == -1) {
        if (SOCKET_ERROR_CODE == SOCKET_EAGAIN ||
            SOCKET_ERROR_CODE == SOCKET_EWOULDBLOCK)
          break;
        continue;
      }

      struct sockaddr *psa = (struct sockaddr *)&sa;

      quicly_decoded_packet_t decoded;
      size_t off = 0;
      while (off < (size_t)rret) {
        if (quicly_decode_packet(&t->quic_ctx, &decoded, buf, rret, &off) ==
            SIZE_MAX)
          break;

        transport_conn_t *target = NULL;
        if (t->is_server) {
          for (size_t i = 0; i < t->conn_count; ++i) {
            if (quicly_is_destination(
                    t->conns[i]->quic,
                    (struct sockaddr *)&t->local_addrs[fd_idx], psa,
                    &decoded)) {
              target = t->conns[i];
              break;
            }
          }
          if (!target && t->conn_count < MAX_CONNECTIONS) {
            quicly_conn_t *new_quic = NULL;
            int accept_res =
                quicly_accept(&new_quic, &t->quic_ctx,
                              (struct sockaddr *)&t->local_addrs[fd_idx], psa,
                              &decoded, NULL, &t->next_cid, NULL, NULL);
            if (accept_res == 0 && new_quic) {
              target = calloc(1, sizeof(transport_conn_t));
              if (!target) {
                quicly_free(new_quic);
                continue;
              }
              target->transport = t;
              target->quic = new_quic;
              *quicly_get_data(new_quic) = target;
              t->conns[t->conn_count++] = target;
            }
          }
        } else {
          target = t->client_conn;
        }

        if (target && target->authenticated && t->simulated_loss_rate > 0 &&
            (rand() % 100) < t->simulated_loss_rate) {
          continue; /* simulate packet loss on wire after connection is
                       established */
        }

        if (target) {
          quicly_receive(target->quic,
                         (struct sockaddr *)&t->local_addrs[fd_idx], psa,
                         &decoded);
        }
      }
    }
  }

  /* run tick timeout for active connections and check sends */
  uint64_t now = ptls_get_time.cb(&ptls_get_time);

  if (now - t->last_pathflow_update >= 25) {
    t->last_pathflow_update = now;

    size_t update_count =
        t->is_server ? t->conn_count : (t->client_conn ? 1U : 0U);
    for (size_t c = 0; c < update_count; c++) {
      transport_conn_t *target = t->is_server ? t->conns[c] : t->client_conn;
      if (!target || !target->quic)
        continue;
      quicly_stats_t stats;
      if (quicly_get_stats(target->quic, &stats) == 0) {
        size_t symbol_size = transport_get_datagram_symbol_size(t);

        /* convert RTT to seconds */
        fp_t l = FP_DIV(FP_FROM_INT(stats.rtt.smoothed), FP_FROM_INT(1000));

        /* convert bandwidth to packets/second */
        size_t cwnd_packets = stats.cc.cwnd / symbol_size;
        if (cwnd_packets == 0)
          cwnd_packets = 1;
        uint32_t rtt_val = stats.rtt.smoothed > 0 ? stats.rtt.smoothed : 1;
        fp_t b = FP_FROM_INT(cwnd_packets * 1000 / rtt_val);
        if (b <= 0) {
          b = FP_FROM_INT(100);
        }

        fp_t p = FP_FROM_FLOAT(0.01f); /* default mock loss rate */
        size_t q = 0; /* bytes in flight or egress queue size */

        for (size_t i = 0; i < t->num_fds; i++) {
          if (target->path_state_overridden[i])
            continue;
          /* use path-specific stats if available, otherwise fallback to
           * connection defaults */
          fp_t path_l = l / 2;
          fp_t path_p = p;
          quicly_path_stats_t path_stats;

          size_t path_idx = transport_path_find_by_link(
              target->quic, t->local_addrs, t->num_fds, i);
          if (quicly_get_path_stats(target->quic, path_idx, &path_stats) == 0) {
            if (path_stats.rtt_smoothed > 0) {
              path_l = FP_DIV(FP_FROM_INT(path_stats.rtt_smoothed),
                              FP_FROM_INT(2000));
            }
            if (path_stats.sent > 0) {
              path_p = FP_DIV(FP_FROM_INT(path_stats.lost),
                              FP_FROM_INT(path_stats.sent));
            }
          }

          if (target->latest_owd_fp[i] > 0) {
            path_l += target->latest_owd_fp[i];
          }

          pathflow_update_state(&target->path_states[i], b, path_l, path_p, q,
                                FP_FROM_FLOAT(0.1f));
        }
      }
    }
  }

  size_t active_count = t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
  for (size_t i = 0; i < active_count; ++i) {
    transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
    if (!conn)
      continue;

    /* check and raise connected event once handshake is ready */
    if (!conn->handshake_complete && quicly_connection_is_ready(conn->quic)) {
      conn->handshake_complete = true;
      transport_event_t ev = {.type = TRANSPORT_EVENT_CONNECTED, .conn = conn};
      t->callback(t->user_data, &ev);
    }

    while (1) {
      quicly_address_t dest, src;
      struct iovec dgrams[64];
      uint8_t dgrams_buf[64 * 1500];
      size_t num_dgrams = 64;
      int send_res = quicly_send(conn->quic, &dest, &src, dgrams, &num_dgrams,
                                 dgrams_buf, sizeof(dgrams_buf));
      if (send_res == 0) {
        if (num_dgrams == 0) {
          if (!quicly_has_datagram_frames(conn->quic))
            memset(conn->queued_datagrams, 0, sizeof(conn->queued_datagrams));
          break;
        }

        size_t sent_path =
            transport_path_find_by_addresses(conn->quic, &src.sa, &dest.sa);
        if (sent_path < TRANSPORT_MAX_QUIC_PATHS)
          conn->queued_datagrams[sent_path] = 0;

        int out_fd = t->fds[0];
        if (src.sa.sa_family == AF_INET) {
          struct sockaddr_in *src_in = (struct sockaddr_in *)&src.sa;
          for (size_t k = 0; k < t->num_fds; k++) {
            if (t->local_addrs[k].ss_family == AF_INET) {
              struct sockaddr_in *loc =
                  (struct sockaddr_in *)&t->local_addrs[k];
              if (loc->sin_addr.s_addr == src_in->sin_addr.s_addr) {
                out_fd = t->fds[k];
                break;
              }
            }
          }
        } else if (src.sa.sa_family == AF_INET6) {
          struct sockaddr_in6 *src_in6 = (struct sockaddr_in6 *)&src.sa;
          for (size_t k = 0; k < t->num_fds; k++) {
            if (t->local_addrs[k].ss_family == AF_INET6) {
              struct sockaddr_in6 *loc =
                  (struct sockaddr_in6 *)&t->local_addrs[k];
              if (memcmp(&loc->sin6_addr, &src_in6->sin6_addr,
                         sizeof(struct in6_addr)) == 0) {
                out_fd = t->fds[k];
                break;
              }
            }
          }
        }

        int udp_result = transport_udp_send_batch(
            out_fd, &dest.sa, quicly_get_socklen(&dest.sa), dgrams, num_dgrams);
        if (udp_result < 0)
          fprintf(stderr, "transport: UDP send failed: %s\n", strerror(errno));
      } else if (send_res == QUICLY_ERROR_FREE_CONNECTION) {
        fprintf(stderr, "Connection %p freed (is_server=%d)\n", conn,
                t->is_server);
        transport_event_t ev = {.type = TRANSPORT_EVENT_DISCONNECTED,
                                .conn = conn};
        t->callback(t->user_data, &ev);

        quicly_free(conn->quic);
        for (size_t a = 0; a < ASSEMBLER_CACHE_SIZE; a++)
          release_assembler(t, &conn->assemblers[a]);
        free(conn);

        if (t->is_server) {
          memmove(t->conns + i, t->conns + i + 1,
                  sizeof(t->conns[0]) * (t->conn_count - i - 1));
          t->conn_count--;
          i--;
          active_count = t->conn_count;
        } else {
          t->client_conn = NULL;
          active_count = 0;
        }
        break;
      } else {
        quicly_close(conn->quic, send_res, "send failure");
        break;
      }
    }
  }
}

typedef struct {
  bool reliable;
  bool fec_enabled;
  bool fec_rateless;
} track_delivery_profile_t;

/* get delivery profile based on track type and name */
static track_delivery_profile_t get_track_profile(const moq_track_id_t *track) {
  track_delivery_profile_t profile = {
      .reliable = (track->flags & MOQ_TRACK_FLAG_RELIABLE) != 0,
      .fec_enabled = (track->flags & MOQ_TRACK_FLAG_FEC_ENABLED) != 0,
      .fec_rateless = (track->flags & MOQ_TRACK_FLAG_FEC_RATELESS) != 0};
  return profile;
}

static bool track_id_is_valid(const moq_track_id_t *track) {
  if (!track ||
      strnlen(track->name, sizeof(track->name)) == sizeof(track->name))
    return false;
  if (!valid_track_type((uint8_t)track->type))
    return false;
  const uint8_t valid_flags = MOQ_TRACK_FLAG_RELIABLE |
                              MOQ_TRACK_FLAG_FEC_ENABLED |
                              MOQ_TRACK_FLAG_FEC_RATELESS;
  return (track->flags & ~valid_flags) == 0;
}

static bool track_id_equal(const moq_track_id_t *a, const moq_track_id_t *b) {
  return a->type == b->type && a->flags == b->flags &&
         strcmp(a->name, b->name) == 0;
}

static transport_publish_result_t
publish_datagram_to_conn(transport_t *t, transport_conn_t *conn,
                         const moq_object_t *obj,
                         const track_delivery_profile_t *profile,
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
  if (total_symbols > FEC_MAX_TOTAL_SYMBOLS || total_symbols > UINT16_MAX)
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
        ++needed[mapped] > QUICLY_PATH_DATAGRAM_QUEUE_CAPACITY ||
        conn->queued_datagrams[mapped] >
            QUICLY_PATH_DATAGRAM_QUEUE_CAPACITY - needed[mapped]) {
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
                                      .send_time_ns = get_time_ns()};
    if (qlinq_wire_encode_fec_header(pkt_buf, pkt_len, &header) !=
        QLINQ_WIRE_OK) {
      transport_arena_reset(&t->arena);
      return queued > 0 ? TRANSPORT_PUBLISH_PARTIAL : TRANSPORT_PUBLISH_ERROR;
    }
    const uint8_t *symbol =
        s < data_symbols ? data_blocks[s] : parity_blocks[s - data_symbols];
    memcpy(pkt_buf + QLINQ_WIRE_FEC_HEADER_SIZE, symbol, symbol_size);
    ptls_iovec_t datagram = ptls_iovec_init(pkt_buf, pkt_len);
    if (!queue_datagram(conn, mapped, datagram)) {
      transport_arena_reset(&t->arena);
      return queued > 0 ? TRANSPORT_PUBLISH_PARTIAL
                        : TRANSPORT_PUBLISH_BACKPRESSURE;
    }
    queued++;
  }

  transport_arena_reset(&t->arena);
  return TRANSPORT_PUBLISH_DELIVERED;
}

static bool flush_fec_buffer(transport_t *t) {
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
  if (!t || !obj || !track_id_is_valid(&obj->track_id) ||
      (obj->size > 0 && !obj->data))
    return TRANSPORT_PUBLISH_INVALID;

  /* route to grouping buffer if it's data and we're not flushing */
  if (obj->track_id.type == MOQ_TRACK_DATA && !t->fec_in_flush) {
    bool use_fec = false;
    if (t->is_server) {
      for (size_t c = 0; c < t->conn_count; c++) {
        transport_conn_t *conn = t->conns[c];
        if (conn && conn->quic &&
            quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING) {
          const track_subscription_t *subscription =
              transport_subscriptions_find_const(&conn->subscriptions,
                                                 &obj->track_id);
          if (subscription) {
            track_delivery_profile_t sub_profile =
                get_track_profile(&subscription->track_id);
            use_fec = sub_profile.fec_enabled || sub_profile.fec_rateless;
          }
          if (use_fec)
            break;
        }
      }
    } else if (t->client_conn) {
      transport_conn_t *conn = t->client_conn;
      const track_subscription_t *subscription =
          transport_subscriptions_find_const(&conn->subscriptions,
                                             &obj->track_id);
      if (subscription) {
        track_delivery_profile_t sub_profile =
            get_track_profile(&subscription->track_id);
        use_fec = sub_profile.fec_enabled || sub_profile.fec_rateless;
      }
    }

    if (use_fec) {
      if (obj->size > TRANSPORT_MAX_FEC_RECORD_SIZE)
        return TRANSPORT_PUBLISH_INVALID;

      if (t->fec_buf_len > 0 &&
          (!track_id_equal(&t->fec_track_id, &obj->track_id) ||
           t->fec_priority != obj->priority)) {
        if (!flush_fec_buffer(t))
          return TRANSPORT_PUBLISH_ERROR;
      }

      if (t->fec_buf_len > 0 &&
          (t->fec_pkt_count >= 4 || obj->size > 16384 - 2 ||
           t->fec_buf_len > 16384 - 2 - obj->size)) {
        if (!flush_fec_buffer(t))
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
        return flush_fec_buffer(t) ? TRANSPORT_PUBLISH_DELIVERED
                                   : TRANSPORT_PUBLISH_ERROR;
      return TRANSPORT_PUBLISH_BUFFERED;
    }
  }

  track_delivery_profile_t profile = get_track_profile(&obj->track_id);

  /* route over reliable stream if requested by profile */
  if (profile.reliable) {
    if (obj->size > TRANSPORT_MAX_RELIABLE_OBJECT_SIZE)
      return TRANSPORT_PUBLISH_INVALID;
    size_t active_count =
        t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
    size_t eligible = 0;
    size_t delivered = 0;
    bool failed = false;
    for (size_t i = 0; i < active_count; ++i) {
      transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
      if (!conn || !conn->quic ||
          quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING)
        continue;
      if (t->is_server && !transport_subscriptions_contains(
                              &conn->subscriptions, &obj->track_id))
        continue;
      eligible++;

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
  if (data_size == 0 || data_size > FEC_MAX_OBJECT_SIZE)
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
    if (!conn || !conn->quic ||
        quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING ||
        (t->is_server && !transport_subscriptions_contains(&conn->subscriptions,
                                                           &obj->track_id)))
      continue;
    eligible++;
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

bool transport_subscribe(transport_t *t, moq_track_id_t track_id) {
  if (!t || !track_id_is_valid(&track_id))
    return false;

  if (t->is_server) {
    for (size_t i = 0; i < t->conn_count; i++) {
      transport_conn_t *conn = t->conns[i];
      if (!conn || !conn->authenticated || !conn->stream ||
          !quicly_sendstate_is_open(&conn->stream->sendstate))
        continue;

      uint8_t alias;
      if (transport_subscriptions_find_alias(&conn->subscriptions, &track_id,
                                             &alias) != 0) {
        if (track_id.name[0] == '\0') {
          alias = (uint8_t)track_id.type;
        } else {
          int next_alias =
              transport_subscriptions_next_alias(&conn->subscriptions, 8);
          if (next_alias < 0)
            return false;
          alias = (uint8_t)next_alias;
        }
        if (!transport_subscriptions_add(&conn->subscriptions, track_id.type,
                                         track_id.flags, track_id.name, alias))
          return false;
      }

      if (!transport_stream_write_track_frame(
              conn->stream, QLINQ_WIRE_SUBSCRIBE, alias, &track_id))
        return false;
    }
    return true;
  }

  if (!t->client_conn || !t->client_conn->authenticated ||
      !t->client_conn->stream ||
      !quicly_sendstate_is_open(&t->client_conn->stream->sendstate)) {
    return false;
  }

  uint8_t alias;
  if (transport_subscriptions_find_alias(&t->client_conn->subscriptions,
                                         &track_id, &alias) != 0) {
    if (track_id.name[0] == '\0') {
      alias = (uint8_t)track_id.type;
    } else {
      int next_alias =
          transport_subscriptions_next_alias(&t->client_conn->subscriptions, 8);
      if (next_alias < 0)
        return false;
      alias = (uint8_t)next_alias;
    }
    if (!transport_subscriptions_add(&t->client_conn->subscriptions,
                                     track_id.type, track_id.flags,
                                     track_id.name, alias))
      return false;
  }

  return transport_stream_write_track_frame(
      t->client_conn->stream, QLINQ_WIRE_SUBSCRIBE, alias, &track_id);
}

bool transport_request_keyframe(transport_t *t, moq_track_id_t track_id) {
  if (!t || !track_id_is_valid(&track_id) || t->is_server || !t->client_conn ||
      !t->client_conn->authenticated || !t->client_conn->stream ||
      !quicly_sendstate_is_open(&t->client_conn->stream->sendstate))
    return false;

  return transport_stream_write_track_frame(
      t->client_conn->stream, QLINQ_WIRE_KEYFRAME_REQUEST, 0, &track_id);
}

bool transport_send_unicast(transport_t *t, transport_conn_t *conn,
                            const void *data, size_t size) {
  if (!t || size > TRANSPORT_MAX_RELIABLE_OBJECT_SIZE || (size > 0 && !data))
    return false;
  if (!conn || !conn->stream ||
      !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;

  return transport_stream_write_frame(conn->stream, QLINQ_WIRE_UNICAST, data,
                                      size);
}

void transport_close_conn(transport_t *t, transport_conn_t *conn) {
  if (!t)
    return;
  if (conn && conn->quic) {
    quicly_close(conn->quic, 0, "");
  }
}

bool transport_send_auth(transport_t *t, transport_conn_t *conn,
                         const uint8_t *token, size_t token_len) {
  if (!t)
    return false;
  if (!conn || !conn->stream ||
      !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;
  if (token_len > 65535 || (token_len > 0 && !token))
    return false;

  return transport_stream_write_frame(conn->stream, QLINQ_WIRE_AUTH_REQUEST,
                                      token, token_len);
}

bool transport_respond_auth(transport_t *t, transport_conn_t *conn,
                            bool success) {
  if (!t)
    return false;
  if (!conn || !conn->stream ||
      !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;

  uint8_t status = success ? 1 : 0;
  if (!transport_stream_write_frame(conn->stream, QLINQ_WIRE_AUTH_RESPONSE,
                                    &status, sizeof(status)))
    return false;

  if (success) {
    conn->authenticated = true;
  } else {
    quicly_close(conn->quic, TRANSPORT_APP_ERROR_AUTHENTICATION,
                 "authentication failed");
  }
  return true;
}

uint64_t transport_get_estimated_bandwidth(transport_t *t) {
  if (!t)
    return 0;
  transport_conn_t *conn =
      t->is_server ? (t->conn_count > 0 ? t->conns[0] : NULL) : t->client_conn;
  if (!conn || !conn->quic) {
    return 0;
  }
  quicly_stats_t stats;
  uint64_t rate = 0;
  if (quicly_get_stats(conn->quic, &stats) == 0) {
    rate = stats.delivery_rate.latest;
  }
  return rate;
}

int transport_enable_qlog(const char *socket_path) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    CLOSE_SOCKET(fd);
    return -1;
  }

  /* Set non-blocking to prevent logging from hanging the main transport thread
   */
  if (!set_fd_nonblocking(fd)) {
    CLOSE_SOCKET(fd);
    return -1;
  }

  /* enable picotls and quicly tracing, sample ratio 1.0 (all logs), write to fd
   */
  ptls_log_add_fd(fd, 1.0, NULL, NULL, NULL, 0);
  ptls_log_add_fd(fd, 1.0, NULL, NULL, NULL, 1);
  return 0;
}

bool transport_get_path_stats(transport_t *t, size_t path_idx,
                              transport_path_stats_t *stats) {
  if (!t || !stats || path_idx >= t->num_fds)
    return false;

  memset(stats, 0, sizeof(*stats));

  transport_conn_t *target =
      t->is_server ? (t->conn_count > 0 ? t->conns[0] : NULL) : t->client_conn;
  if (target && target->quic) {
    quicly_path_stats_t path_stats;
    size_t mapped_path_idx = transport_path_find_by_link(
        target->quic, t->local_addrs, t->num_fds, path_idx);
    if (quicly_get_path_stats(target->quic, mapped_path_idx, &path_stats) ==
        0) {
      stats->sent = path_stats.sent;
      stats->lost = path_stats.lost;
      stats->rtt = path_stats.rtt_smoothed;
    }
  }

  stats->relative_owd =
      target ? (double)FP_TO_FLOAT(target->latest_owd_fp[path_idx]) * 1000.0
             : 0.0;
  stats->ewma_latency =
      target
          ? (double)FP_TO_FLOAT(target->path_states[path_idx].l_ewma) * 1000.0
          : 0.0;

  return true;
}

/* mock a local IP interface addition for testing multipath */
void transport_mock_iface_add(transport_t *t, const char *ip_addr) {
  if (!t || t->ifmon_pipe[1] < 0)
    return;

  ifmon_pipe_msg_t msg = {0};
  msg.is_added = 1;
  msg.index = 1; /* loopback interface index */
  struct sockaddr_in *sin = (struct sockaddr_in *)&msg.addr;
  sin->sin_family = AF_INET;
  inet_pton(AF_INET, ip_addr, &sin->sin_addr);
  msg.addr_len = sizeof(*sin);

  ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
  (void)w;
}

bool transport_mock_path_state(transport_t *t, size_t path_idx,
                               uint32_t packets_per_second, double latency_ms,
                               double loss_rate) {
  if (!t || path_idx >= t->num_fds || packets_per_second == 0 ||
      latency_ms < 0.0 || loss_rate < 0.0 || loss_rate > 1.0)
    return false;
  size_t active_count = t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
  if (active_count == 0)
    return false;
  for (size_t i = 0; i < active_count; i++) {
    transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
    if (!conn)
      continue;
    path_state_t *state = &conn->path_states[path_idx];
    state->initialized = 1;
    state->b_ewma = FP_FROM_INT(packets_per_second);
    state->l_ewma = FP_FROM_FLOAT((float)(latency_ms / 1000.0));
    state->p_ewma = FP_FROM_FLOAT((float)loss_rate);
    state->q_ewma = 0;
    conn->path_state_overridden[path_idx] = true;
  }
  return true;
}

size_t transport_get_datagram_symbol_size(const transport_t *t) {
  if (!t)
    return 0;
  size_t symbol_size = 1100;
  if (t->quic_ctx.initial_egress_max_udp_payload_size > 80)
    symbol_size = t->quic_ctx.initial_egress_max_udp_payload_size - 80;
  return symbol_size < 1000 ? 1000 : symbol_size;
}

bool transport_is_track_ready(transport_t *t, const moq_track_id_t *track_id) {
  if (!t || !track_id_is_valid(track_id))
    return false;

  track_delivery_profile_t profile = get_track_profile(track_id);

  size_t active_count = t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
  if (active_count == 0)
    return true; /* no peers means data is dropped anyway, so it's "ready" */

  bool all_ready = true;
  for (size_t c = 0; c < active_count; c++) {
    transport_conn_t *conn = t->is_server ? t->conns[c] : t->client_conn;
    if (!conn || !conn->quic ||
        quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING)
      continue;

    if (!conn->authenticated)
      return false;

    if (t->is_server &&
        !transport_subscriptions_contains(&conn->subscriptions, track_id))
      continue;

    if (profile.reliable) {
      const track_subscription_t *subscription =
          transport_subscriptions_find_const(&conn->subscriptions, track_id);
      quicly_stream_t *stream = subscription ? subscription->stream : NULL;

      if (stream) {
        quicly_streambuf_t *sbuf = (quicly_streambuf_t *)stream->data;
        if (sbuf && sbuf->egress.vecs.size > 256) {
          all_ready = false;
          break;
        }
      }
    } else {
      for (size_t p = 0; p < TRANSPORT_MAX_QUIC_PATHS; p++) {
        if (conn->queued_datagrams[p] >=
            QUICLY_PATH_DATAGRAM_QUEUE_CAPACITY * 3 / 4) {
          all_ready = false;
          break;
        }
      }
      if (!all_ready)
        break;
      quicly_path_stats_t pstats;
      if (quicly_get_path_stats(conn->quic, 0, &pstats) == 0) {
        if (pstats.bytes_in_flight >= pstats.cwnd * 2) {
          all_ready = false;
          break;
        }
      }
    }
  }

  return all_ready;
}

int64_t transport_get_time_ms(void) {
  return (int64_t)ptls_get_time.cb(&ptls_get_time);
}

int64_t transport_get_first_timeout(transport_t *t) {
  if (!t)
    return INT64_MAX;

  int64_t first_timeout = INT64_MAX;

  if (t->client_conn && t->client_conn->quic) {
    int64_t to = quicly_get_first_timeout(t->client_conn->quic);
    if (to < first_timeout)
      first_timeout = to;
  }

  for (size_t i = 0; i < t->conn_count; i++) {
    if (t->conns[i] && t->conns[i]->quic) {
      int64_t to = quicly_get_first_timeout(t->conns[i]->quic);
      if (to < first_timeout)
        first_timeout = to;
    }
  }

  return first_timeout;
}

size_t transport_get_poll_fds(transport_t *t, struct pollfd *fds,
                              size_t max_fds) {
  if (!t || !fds)
    return 0;

  size_t count = 0;
  for (size_t i = 0; i < t->num_fds && count < max_fds; i++) {
    if (t->fds[i] >= 0) {
      fds[count].fd = t->fds[i];
      fds[count].events = POLLIN;
      fds[count].revents = 0;
      count++;
    }
  }
  return count;
}
