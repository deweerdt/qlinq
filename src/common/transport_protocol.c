#include "transport_protocol.h"

#include "fec.h"
#include "transport_repair.h"
#include "transport_stream.h"
#include "transport_wire.h"

#include "quicly/sendstate.h"
#include "quicly/streambuf.h"

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool transport_track_type_valid(uint8_t type) {
  return type == MOQ_TRACK_VIDEO || type == MOQ_TRACK_AUDIO ||
         type == MOQ_TRACK_INPUT || type == MOQ_TRACK_TEXT ||
         type == MOQ_TRACK_DATA || type == MOQ_TRACK_TELEMETRY;
}

static uint32_t local_capabilities(void) {
  return QLINQ_WIRE_CAP_RELIABLE | QLINQ_WIRE_CAP_DATAGRAM |
         QLINQ_WIRE_CAP_FEC_REED_SOLOMON | QLINQ_WIRE_CAP_FEC_RATELESS |
         QLINQ_WIRE_CAP_MULTIPATH | QLINQ_WIRE_CAP_AUTHENTICATION;
}

bool transport_protocol_send_hello(transport_conn_t *conn) {
  if (!conn || conn->hello_sent || !conn->stream ||
      !quicly_sendstate_is_open(&conn->stream->sendstate))
    return conn && conn->hello_sent;
  transport_t *t = conn->transport;
  size_t datagram_size = t->limits.max_udp_payload_size;
  if (datagram_size > UINT16_MAX)
    datagram_size = UINT16_MAX;
  qlinq_wire_hello_t hello = {
      .role = t->is_server ? QLINQ_WIRE_ROLE_SERVER : QLINQ_WIRE_ROLE_CLIENT,
      .max_paths = (uint16_t)t->num_fds,
      .capabilities = local_capabilities(),
      .max_reliable_object_size = (uint32_t)t->limits.max_reliable_object_size,
      .max_fec_object_size = (uint32_t)t->limits.max_fec_object_size,
      .max_subscriptions = (uint16_t)t->limits.max_subscriptions_per_connection,
      .max_datagram_size = (uint16_t)datagram_size};
  uint8_t payload[QLINQ_WIRE_HELLO_SIZE];
  if (qlinq_wire_encode_hello(payload, sizeof(payload), &hello) !=
          QLINQ_WIRE_OK ||
      !transport_stream_write_frame(conn->stream, QLINQ_WIRE_HELLO, payload,
                                    sizeof(payload)))
    return false;
  conn->hello_sent = true;
  return true;
}

void transport_protocol_maybe_emit_connected(transport_conn_t *conn) {
  if (!conn || conn->connected_emitted || !conn->quic_ready ||
      !conn->protocol_ready)
    return;
  conn->connected_emitted = true;
  conn->transport->stats.protocol_handshakes_completed++;
  transport_event_t event = {.type = TRANSPORT_EVENT_CONNECTED, .conn = conn};
  transport_emit_event(conn->transport, &event);
}

static bool receive_hello(transport_conn_t *conn, const uint8_t *payload,
                          size_t payload_len) {
  if (!conn || conn->hello_received)
    return false;
  qlinq_wire_hello_t hello;
  if (qlinq_wire_decode_hello(payload, payload_len, &hello) != QLINQ_WIRE_OK)
    return false;
  transport_t *t = conn->transport;
  uint8_t expected_role =
      t->is_server ? QLINQ_WIRE_ROLE_CLIENT : QLINQ_WIRE_ROLE_SERVER;
  uint32_t required = QLINQ_WIRE_CAP_RELIABLE | QLINQ_WIRE_CAP_DATAGRAM;
  if (hello.role != expected_role ||
      (hello.capabilities & required) != required)
    return false;

  conn->peer_capabilities = hello.capabilities;
  conn->negotiated_limits = t->limits;
  if (conn->negotiated_limits.max_reliable_object_size >
      hello.max_reliable_object_size)
    conn->negotiated_limits.max_reliable_object_size =
        hello.max_reliable_object_size;
  if (conn->negotiated_limits.max_fec_object_size > hello.max_fec_object_size)
    conn->negotiated_limits.max_fec_object_size = hello.max_fec_object_size;
  if (conn->negotiated_limits.max_subscriptions_per_connection >
      hello.max_subscriptions)
    conn->negotiated_limits.max_subscriptions_per_connection =
        hello.max_subscriptions;
  if (conn->negotiated_limits.max_udp_payload_size > hello.max_datagram_size)
    conn->negotiated_limits.max_udp_payload_size = hello.max_datagram_size;
  conn->hello_received = true;
  if (!transport_protocol_send_hello(conn))
    return false;
  conn->protocol_ready = true;
  transport_protocol_maybe_emit_connected(conn);
  return true;
}

static void close_wire_error(transport_conn_t *conn,
                             qlinq_wire_result_t result) {
  const char *reason = result == QLINQ_WIRE_UNSUPPORTED_VERSION
                           ? "protocol version mismatch"
                           : "protocol error: malformed frame";
  conn->transport->stats.protocol_errors++;
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
  conn->transport->stats.repair_requests_received++;
  if (conn->repair_requests_in_window >=
      conn->transport->limits.max_repair_requests_per_second) {
    conn->transport->stats.repair_requests_throttled++;
    return false;
  }
  if (conn->last_repair_ms != 0 &&
      now - conn->last_repair_ms < QLINQ_FEC_REPAIR_DEDUP_MS &&
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

static bool object_was_delivered(const transport_object_gap_state_t *state,
                                 uint64_t object_id) {
  if (!state->delivered_initialized || object_id > state->largest_delivered)
    return false;
  uint64_t distance = state->largest_delivered - object_id;
  if (distance >= QLINQ_RECOVERY_HISTORY_OBJECTS)
    return true;
  return (state->delivered_mask[distance / 64U] &
          (UINT64_C(1) << (distance % 64U))) != 0;
}

static void mark_object_delivered(transport_object_gap_state_t *state,
                                  uint64_t object_id) {
  if (!state->delivered_initialized) {
    state->delivered_initialized = true;
    state->largest_delivered = object_id;
    state->delivered_mask[0] = 1;
    return;
  }
  if (object_id > state->largest_delivered) {
    uint64_t distance = object_id - state->largest_delivered;
    uint64_t shifted[QLINQ_RECOVERY_HISTORY_OBJECTS / 64U] = {0};
    if (distance < QLINQ_RECOVERY_HISTORY_OBJECTS) {
      size_t word_shift = (size_t)(distance / 64U);
      unsigned bit_shift = (unsigned)(distance % 64U);
      for (size_t dst = QLINQ_RECOVERY_HISTORY_OBJECTS / 64U; dst-- > 0;) {
        if (dst < word_shift)
          continue;
        size_t src = dst - word_shift;
        shifted[dst] = state->delivered_mask[src] << bit_shift;
        if (bit_shift != 0 && src > 0)
          shifted[dst] |= state->delivered_mask[src - 1U] >> (64U - bit_shift);
      }
    }
    memcpy(state->delivered_mask, shifted, sizeof(shifted));
    state->delivered_mask[0] |= 1;
    state->largest_delivered = object_id;
  } else {
    uint64_t distance = state->largest_delivered - object_id;
    if (distance < QLINQ_RECOVERY_HISTORY_OBJECTS)
      state->delivered_mask[distance / 64U] |= UINT64_C(1) << (distance % 64U);
  }
}

static bool queue_missing_objects(transport_object_gap_state_t *state,
                                  uint64_t group_id, uint64_t first_missing,
                                  uint64_t missing_count) {
  if (!state || missing_count == 0)
    return true;
  if (missing_count > 32)
    return false;
  if (state->pending_mask == 0) {
    state->pending_base = first_missing;
    state->detected_at_ms = transport_get_time_ms();
    state->group_id = group_id;
  }
  if (first_missing < state->pending_base ||
      first_missing - state->pending_base >= 32)
    return false;
  uint32_t offset = (uint32_t)(first_missing - state->pending_base);
  uint32_t available = 32 - offset;
  uint32_t count =
      missing_count < available ? (uint32_t)missing_count : available;
  uint32_t bits = count == 32 ? UINT32_MAX : ((1U << count) - 1U);
  state->pending_mask |= bits << offset;
  return count == missing_count;
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
    t->stats.stream_frames_received++;
    conn->stream_frames_received++;
    if (type != QLINQ_WIRE_HELLO && !conn->hello_received) {
      t->stats.protocol_errors++;
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                   "protocol error: HELLO must be first");
      break;
    }
    if (type == QLINQ_WIRE_HELLO) {
      if (conn->stream_frames_received != 1 ||
          !receive_hello(conn, input.base, input.len)) {
        t->stats.protocol_errors++;
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: invalid HELLO");
        break;
      }
      quicly_streambuf_ingress_shift(stream, frame.consumed);
    } else if (type == QLINQ_WIRE_SUBSCRIBE || type == QLINQ_WIRE_UNSUBSCRIBE ||
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
      if (!transport_track_type_valid(track_type) ||
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
        moq_track_id_t aliased_track;
        if (transport_subscriptions_find_by_alias(&conn->subscriptions, alias,
                                                  &aliased_track) == 0 &&
            (aliased_track.type != parsed_track.type ||
             strcmp(aliased_track.name, parsed_track.name) != 0)) {
          t->stats.protocol_errors++;
          quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                       "protocol error: track alias collision");
          break;
        }
        quicly_debug_printf(
            conn->quic,
            "Subscription mapping: track '%s' (type %d) mapped to alias %d",
            wire_track.name, track_type, alias);
        if (!transport_subscriptions_add(&conn->subscriptions,
                                         (moq_track_type_t)track_type, flags,
                                         wire_track.name, alias)) {
          t->stats.resource_limit_errors++;
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
      transport_emit_event(t, &ev);
      quicly_streambuf_ingress_shift(stream, frame.consumed);
    } else if (type == QLINQ_WIRE_UNICAST) {
      size_t payload_size = input.len;
      if (payload_size > conn->negotiated_limits.max_reliable_object_size) {
        t->stats.resource_limit_errors++;
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
      transport_emit_event(t, &ev);
      quicly_streambuf_ingress_shift(stream, frame.consumed);
    } else if (type == QLINQ_WIRE_AUTH_REQUEST) {
      size_t token_len = input.len;
      if (token_len > UINT16_MAX) {
        t->stats.resource_limit_errors++;
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
      transport_emit_event(t, &ev);
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
      transport_emit_event(t, &ev);
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
            uint16_t missing[TRANSPORT_REPAIR_MAX_SYMBOLS] = {0};
            size_t missing_count = nack.missing_count;
            if (missing_count > TRANSPORT_REPAIR_MAX_SYMBOLS)
              missing_count = TRANSPORT_REPAIR_MAX_SYMBOLS;
            bool indices_valid = true;
            for (size_t i = 0; i < missing_count; i++) {
              if (!qlinq_wire_nack_index(&nack, i, &missing[i]) ||
                  missing[i] >= QLINQ_FEC_MAX_TOTAL_SYMBOLS) {
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
                uint8_t packet[QLINQ_WIRE_FEC_HEADER_SIZE +
                               QLINQ_FEC_MAX_SYMBOL_SIZE];
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
                    .send_time_ns = transport_get_time_ns()};
                if (qlinq_wire_encode_fec_header(packet, sizeof(packet),
                                                 &header) != QLINQ_WIRE_OK)
                  break;
                memcpy(packet + QLINQ_WIRE_FEC_HEADER_SIZE,
                       repair.symbols + i * repair.symbol_size,
                       repair.symbol_size);
                ptls_iovec_t datagram = ptls_iovec_init(packet, packet_len);
                if (!transport_queue_datagram(conn, 0, datagram))
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
    t->stats.stream_frames_received++;
    conn->stream_frames_received++;
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
    if (payload_size > conn->negotiated_limits.max_reliable_object_size) {
      t->stats.resource_limit_errors++;
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_RESOURCE_LIMIT,
                   "protocol error: reliable object too large");
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
      transport_emit_event(t, &ev);
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
bool transport_protocol_send_nack(transport_conn_t *conn, uint8_t alias,
                                  uint64_t group_id, uint64_t object_id,
                                  const uint16_t *missing, uint16_t count,
                                  bool whole_object) {
  if (!conn || !conn->stream ||
      !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;

  if (count > QLINQ_WIRE_MAX_NACK_SYMBOLS)
    return false;
  size_t payload_len = 20U + (size_t)count * 2U;
  uint8_t static_buf[1024];
  uint8_t *buf = static_buf;
  if (payload_len > sizeof(static_buf)) {
    buf = malloc(payload_len);
    if (!buf)
      return false;
  }

  size_t written = 0;
  bool sent = false;
  uint8_t flags = whole_object ? QLINQ_WIRE_NACK_WHOLE_OBJECT : 0;
  if (qlinq_wire_encode_nack(buf, payload_len, alias, flags, group_id,
                             object_id, missing, count,
                             &written) == QLINQ_WIRE_OK &&
      transport_stream_write_frame(conn->stream, QLINQ_WIRE_NACK, buf,
                                   written))
    sent = true;

  if (buf != static_buf) {
    free(buf);
  }
  return sent;
}

static void on_receive_datagram_frame(quicly_receive_datagram_frame_t *self,
                                      quicly_conn_t *conn,
                                      ptls_iovec_t payload) {
  (void)self;
  transport_conn_t *tconn = *quicly_get_data(conn);
  if (!tconn)
    return;

  transport_t *t = tconn->transport;
  t->stats.datagrams_received++;
  tconn->datagrams_received++;
  if (!tconn->authenticated)
    return;

  uint8_t datagram_type;
  qlinq_wire_result_t wire_result = qlinq_wire_decode_datagram_type(
      payload.base, payload.len, &datagram_type);
  if (wire_result != QLINQ_WIRE_OK) {
    t->stats.malformed_datagrams++;
    tconn->malformed_datagrams++;
    return;
  }

  if (datagram_type == QLINQ_WIRE_DATAGRAM_TELEMETRY) {
    qlinq_wire_telemetry_t telemetry;
    if (qlinq_wire_decode_telemetry(payload.base, payload.len, &telemetry) !=
        QLINQ_WIRE_OK) {
      t->stats.malformed_datagrams++;
      tconn->malformed_datagrams++;
      return;
    }
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
      QLINQ_WIRE_OK) {
    t->stats.malformed_datagrams++;
    tconn->malformed_datagrams++;
    return;
  }

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
                                      .recv_time_ns = transport_get_time_ns()};
  if (qlinq_wire_encode_telemetry(reply, sizeof(reply), &telemetry) ==
      QLINQ_WIRE_OK) {
    ptls_iovec_t reply_vec = ptls_iovec_init(reply, sizeof(reply));
    (void)transport_queue_datagram(tconn, hdr.path_id, reply_vec);
  }

  uint8_t is_keyframe = hdr.is_keyframe;
  uint64_t group_id = hdr.group_id;
  uint64_t object_id = hdr.object_id;
  uint16_t symbol_index = hdr.symbol_index;
  uint16_t total_symbols = hdr.total_symbols;
  uint16_t data_symbols = hdr.data_symbols;
  uint16_t symbol_size = hdr.symbol_size;
  uint32_t original_size = hdr.original_size;

  if (total_symbols == 0 || total_symbols > QLINQ_FEC_MAX_TOTAL_SYMBOLS ||
      symbol_size == 0 || symbol_size > QLINQ_FEC_MAX_SYMBOL_SIZE ||
      data_symbols == 0 || data_symbols > total_symbols ||
      symbol_index >= total_symbols)
    goto malformed_datagram;

  if (original_size > tconn->negotiated_limits.max_fec_object_size ||
      original_size > (uint32_t)data_symbols * symbol_size ||
      original_size == 0)
    goto malformed_datagram;

  if (payload.len != QLINQ_WIRE_FEC_HEADER_SIZE + symbol_size)
    goto malformed_datagram;

  bool rateless_data =
      resolved_track.type == MOQ_TRACK_DATA &&
      (resolved_track.flags & MOQ_TRACK_FLAG_FEC_RATELESS) != 0;
  transport_object_gap_state_t *object_state = &tconn->object_gaps[track_id];
  if (rateless_data && object_was_delivered(object_state, object_id)) {
    t->stats.fec_duplicate_objects_suppressed++;
    return;
  }

  if (rateless_data) {
    transport_object_gap_state_t *gap = object_state;
    if (!gap->seen_initialized) {
      gap->seen_initialized = true;
      gap->last_seen = object_id;
    } else if (object_id > gap->last_seen) {
      if (object_id - gap->last_seen > 1) {
        uint64_t first_missing = gap->last_seen + 1;
        uint64_t missing_count = object_id - first_missing;
        (void)queue_missing_objects(gap, group_id, first_missing,
                                    missing_count);
      }
      gap->last_seen = object_id;
    } else if (gap->pending_mask != 0 && object_id >= gap->pending_base &&
               object_id - gap->pending_base < 32) {
      gap->pending_mask &= ~(1U << (object_id - gap->pending_base));
    }
  }

  /* lookup active frame assembler cache */
  frame_assembler_t *asm_slot = NULL;
  for (size_t i = 0; i < t->limits.max_assemblers_per_connection; i++) {
    frame_assembler_t *a = &tconn->assemblers[i];
    if (a->total_symbols > 0 && a->track_id == track_id &&
        a->group_id == group_id && a->object_id == object_id) {
      if (a->symbol_size != symbol_size || a->data_symbols != data_symbols ||
          a->original_size != original_size) {
        goto malformed_datagram;
      }
      asm_slot = a;
      break;
    }
  }

  if (!asm_slot) {
    asm_slot = &tconn->assemblers[tconn->assembler_index];
    tconn->assembler_index =
        (tconn->assembler_index + 1) % t->limits.max_assemblers_per_connection;

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
        t->stats.fec_objects_lost++;
        transport_emit_event(tconn->transport, &ev);
      }
    }

    if (!asm_slot->buffers || asm_slot->capacity_symbols < total_symbols ||
        asm_slot->capacity_symbol_size < symbol_size) {
      transport_release_assembler(t, asm_slot);
      if (!transport_grow_assembler(t, asm_slot, total_symbols, symbol_size)) {
        transport_release_assembler(t, asm_slot);
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
    if (!transport_grow_assembler(t, asm_slot, total_symbols, symbol_size)) {
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
        fec_type_t fec_type = rateless_data || total_symbols > 255
                                  ? FEC_RAPTORQ
                                  : FEC_REED_SOLOMON;
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
      if (rateless_data)
        mark_object_delivered(object_state, object_id);
      t->stats.fec_objects_recovered++;
      transport_emit_event(t, &ev);
      free(full_data);
      transport_release_assembler(t, asm_slot);
    }
  }
  return;

malformed_datagram:
  t->stats.malformed_datagrams++;
  tconn->malformed_datagrams++;
}

void transport_protocol_setup(transport_t *t) {
  if (!t)
    return;
  t->stream_open.cb = on_stream_open;
  t->receive_datagram.cb = on_receive_datagram_frame;
}
