/* qlinq-app: direct transport API file and stream bridge. */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "portable_sockets.h"
#include "transport.h"

#include <errno.h>
#include <inttypes.h>
#include <openssl/crypto.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define APP_REORDER_OBJECTS 256U
#define APP_REORDER_MAX_BYTES (64U * 1024U * 1024U)

typedef struct {
  uint8_t *data;
  size_t size;
  uint64_t object_id;
  bool active;
} reorder_entry_t;

typedef struct {
  transport_t *transport;
  moq_track_id_t track;
  const uint8_t *auth_token;
  size_t auth_token_len;
  FILE *input;
  FILE *output;
  FILE *stats_output;
  const char *node_id;
  uint8_t *message;
  size_t message_capacity;
  size_t pending_size;
  uint64_t next_object_id;
  uint64_t sent_records;
  uint64_t received_records;
  uint64_t received_bytes;
  uint64_t count_limit;
  uint64_t receive_limit;
  size_t subscriptions;
  size_t required_subscriptions;
  uint32_t interval_ms;
  uint32_t drain_ms;
  uint32_t stats_ms;
  int64_t next_send_at;
  int64_t next_stats_at;
  int64_t finished_at;
  int64_t received_at;
  int64_t started_at;
  bool is_server;
  bool input_eof;
  bool track_finished;
  bool one_shot;
  bool verbose;
  bool failed;
  bool reorder_initialized;
  uint64_t reorder_group_id;
  uint64_t reorder_next_object_id;
  size_t reorder_bytes;
  reorder_entry_t reorder[APP_REORDER_OBJECTS];
} app_t;

static volatile sig_atomic_t running = 1;

static void handle_signal(int sig) {
  (void)sig;
  running = 0;
}

static void show_help(FILE *out, const char *program) {
  fprintf(out,
          "usage: %s (--listen PORT | --peer HOST[:PORT]) [options]\n\n"
          "Network:\n"
          "  --bind ADDRESS              numeric local address\n"
          "  --cert FILE --key FILE      local TLS identity\n"
          "  --ca FILE                   peer CA bundle\n"
          "  --auth-token TOKEN          application authentication token\n"
          "  --insecure-no-verify        test-only certificate bypass\n"
          "  --idle-timeout-ms MS        QUIC session idle timeout\n"
          "  --max-connections N         listener connection capacity\n"
          "  --max-repair-requests N     per-peer repair requests/second\n"
          "  --max-aggregate-repairs N   source-wide repair requests/second\n"
          "  --loss PERCENT              simulated inbound packet loss\n\n"
          "Data:\n"
          "  --track NAME                default qlinq-app/data\n"
          "  --mode datagram|fec|rateless|reliable\n"
          "  --repair-mode auto|indexed|rateless\n"
          "  --input FILE|-              publish fixed-size records\n"
          "  --output FILE|-             write received records\n"
          "  --message-size BYTES        default 1200\n"
          "  --count N                   stop after N sent records\n"
          "  --receive-count N           exit after N received records\n"
          "  --wait-subscribers N        default 1 when publishing\n"
          "  --interval-ms MS            minimum send interval\n"
          "  --one-shot                  exit after input and drain\n"
          "  --drain-ms MS               default 1000\n"
          "  --stats-ms MS               periodically print counters\n"
          "  --stats-file FILE           write TSV counter snapshots\n"
          "  --node-id ID                TSV node label\n"
          "  --verbose\n",
          program);
}

static bool parse_u64(const char *text, uint64_t maximum, uint64_t *value) {
  char *end = NULL;
  if (!text || !text[0] || text[0] == '-' || !value)
    return false;
  errno = 0;
  unsigned long long parsed = strtoull(text, &end, 10);
  if (errno != 0 || !end || *end != '\0' || parsed > maximum)
    return false;
  *value = (uint64_t)parsed;
  return true;
}

static bool parse_peer(const char *endpoint, char *host, size_t capacity,
                       uint16_t *port) {
  const char *start = endpoint;
  const char *port_text = NULL;
  size_t host_len;
  uint64_t parsed_port;
  if (!endpoint || !endpoint[0] || !host || capacity == 0 || !port)
    return false;
  host_len = strlen(endpoint);
  if (endpoint[0] == '[') {
    const char *closing = strchr(endpoint + 1, ']');
    if (!closing || (closing[1] != '\0' && closing[1] != ':'))
      return false;
    start = endpoint + 1;
    host_len = (size_t)(closing - start);
    if (closing[1] == ':')
      port_text = closing + 2;
  } else {
    const char *first = strchr(endpoint, ':');
    const char *last = strrchr(endpoint, ':');
    if (first && first == last) {
      host_len = (size_t)(first - endpoint);
      port_text = first + 1;
    }
  }
  if (host_len == 0 || host_len >= capacity)
    return false;
  if (port_text &&
      (!parse_u64(port_text, UINT16_MAX, &parsed_port) || parsed_port == 0))
    return false;
  if (port_text)
    *port = (uint16_t)parsed_port;
  memcpy(host, start, host_len);
  host[host_len] = '\0';
  return true;
}

static bool write_payload(app_t *app, const moq_track_id_t *track,
                          const uint8_t *data, size_t size) {
  if (track->type == MOQ_TRACK_DATA &&
      (track->flags & MOQ_TRACK_FLAG_FEC_ENABLED) != 0) {
    while (size != 0) {
      uint16_t record_size;
      if (size < 2)
        return false;
      memcpy(&record_size, data, sizeof(record_size));
      record_size = ntohs(record_size);
      data += 2;
      size -= 2;
      if (record_size == 0 || record_size > size)
        return false;
      if (app->output &&
          fwrite(data, 1, record_size, app->output) != record_size)
        return false;
      app->received_records++;
      app->received_bytes += record_size;
      data += record_size;
      size -= record_size;
    }
  } else {
    if (app->output && size != 0 && fwrite(data, 1, size, app->output) != size)
      return false;
    app->received_records++;
    app->received_bytes += size;
  }
  if (app->output)
    fflush(app->output);
  if (app->receive_limit != 0 && app->received_records >= app->receive_limit &&
      app->received_at == 0)
    app->received_at = transport_get_time_ms();
  return true;
}

static bool write_object(app_t *app, const transport_event_t *event) {
  bool ordered = event->track_id.type == MOQ_TRACK_DATA &&
                 (event->track_id.flags & MOQ_TRACK_FLAG_FEC_ENABLED) != 0;
  if (!ordered)
    return write_payload(app, &event->track_id, event->object.data,
                         event->object.size);
  if (!app->reorder_initialized) {
    app->reorder_initialized = true;
    app->reorder_group_id = event->object.group_id;
    app->reorder_next_object_id = 0;
  }
  if (event->object.group_id != app->reorder_group_id ||
      event->object.object_id < app->reorder_next_object_id)
    return event->object.group_id == app->reorder_group_id;
  uint64_t distance = event->object.object_id - app->reorder_next_object_id;
  if (distance >= APP_REORDER_OBJECTS ||
      event->object.size > APP_REORDER_MAX_BYTES - app->reorder_bytes)
    return false;
  size_t slot = (size_t)(event->object.object_id % APP_REORDER_OBJECTS);
  reorder_entry_t *entry = &app->reorder[slot];
  if (entry->active)
    return entry->object_id == event->object.object_id;
  entry->data = malloc(event->object.size);
  if (!entry->data)
    return false;
  memcpy(entry->data, event->object.data, event->object.size);
  entry->size = event->object.size;
  entry->object_id = event->object.object_id;
  entry->active = true;
  app->reorder_bytes += entry->size;

  while (true) {
    slot = (size_t)(app->reorder_next_object_id % APP_REORDER_OBJECTS);
    entry = &app->reorder[slot];
    if (!entry->active || entry->object_id != app->reorder_next_object_id)
      break;
    if (!write_payload(app, &event->track_id, entry->data, entry->size))
      return false;
    app->reorder_bytes -= entry->size;
    free(entry->data);
    memset(entry, 0, sizeof(*entry));
    app->reorder_next_object_id++;
  }
  return true;
}

static void subscribe(app_t *app, transport_conn_t *conn) {
  if (!transport_subscribe_conn(app->transport, conn, app->track)) {
    fprintf(stderr, "qlinq-app: unable to subscribe to '%s'\n",
            app->track.name);
    app->failed = true;
  }
}

static void on_event(void *user_data, const transport_event_t *event) {
  app_t *app = user_data;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    if (app->verbose)
      fprintf(stderr, "qlinq-app: peer connected\n");
    if (!app->is_server &&
        !transport_send_auth(app->transport, event->conn, app->auth_token,
                             app->auth_token_len))
      app->failed = true;
    break;
  case TRANSPORT_EVENT_AUTH: {
    bool accepted = app->is_server &&
                    event->auth.token_len == app->auth_token_len &&
                    CRYPTO_memcmp(event->auth.token, app->auth_token,
                                  app->auth_token_len) == 0;
    if (!transport_respond_auth(app->transport, event->conn, accepted))
      app->failed = true;
    if (accepted)
      subscribe(app, event->conn);
    break;
  }
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    if (event->auth.success)
      subscribe(app, event->conn);
    else
      app->failed = true;
    break;
  case TRANSPORT_EVENT_SUBSCRIBE:
    if (event->track_id.type == app->track.type &&
        strcmp(event->track_id.name, app->track.name) == 0)
      app->subscriptions++;
    break;
  case TRANSPORT_EVENT_UNSUBSCRIBE:
    if (event->track_id.type == app->track.type &&
        strcmp(event->track_id.name, app->track.name) == 0 &&
        app->subscriptions != 0)
      app->subscriptions--;
    break;
  case TRANSPORT_EVENT_OBJECT:
    if (event->track_id.type == app->track.type &&
        strcmp(event->track_id.name, app->track.name) == 0 &&
        !write_object(app, event)) {
      fprintf(stderr, "qlinq-app: malformed object or output error\n");
      app->failed = true;
    }
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    if (app->verbose)
      fprintf(stderr, "qlinq-app: peer disconnected\n");
    break;
  case TRANSPORT_EVENT_OBJECT_LOST:
    if (app->verbose)
      fprintf(stderr, "qlinq-app: object recovery failed\n");
    break;
  case TRANSPORT_EVENT_KEYFRAME_REQUEST:
    break;
  }
}

static void publish_pending(app_t *app, int64_t now) {
  if (app->pending_size == 0 || now < app->next_send_at)
    return;
  moq_object_t object = {.track_id = app->track,
                         .group_id = 0,
                         .object_id = app->next_object_id,
                         .data = app->message,
                         .size = app->pending_size,
                         .priority = 1};
  transport_publish_result_t result =
      transport_publish_ex(app->transport, &object);
  if (result == TRANSPORT_PUBLISH_BACKPRESSURE)
    return;
  if (result == TRANSPORT_PUBLISH_INVALID ||
      result == TRANSPORT_PUBLISH_ERROR ||
      result == TRANSPORT_PUBLISH_PARTIAL) {
    fprintf(stderr, "qlinq-app: publication failed (%d)\n", result);
    app->failed = true;
    return;
  }
  app->pending_size = 0;
  app->next_object_id++;
  app->sent_records++;
  app->next_send_at = now + app->interval_ms;
}

static void load_input(app_t *app, bool ready) {
  if (!ready || !app->input || app->input_eof || app->pending_size != 0 ||
      app->subscriptions < app->required_subscriptions)
    return;
  if (app->count_limit != 0 && app->sent_records >= app->count_limit) {
    app->input_eof = true;
    return;
  }
  ssize_t n = read(fileno(app->input), app->message, app->message_capacity);
  if (n > 0) {
    app->pending_size = (size_t)n;
  } else if (n == 0) {
    app->input_eof = true;
  } else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
    fprintf(stderr, "qlinq-app: input read failed: %s\n", strerror(errno));
    app->failed = true;
  }
}

static void finish_track(app_t *app, int64_t now) {
  if (!app->input_eof || app->pending_size != 0 || app->track_finished)
    return;
  if ((app->track.flags & MOQ_TRACK_FLAG_FEC_RATELESS) != 0 &&
      !transport_finish_track(app->transport, app->track))
    return;
  app->track_finished = true;
  app->finished_at = now;
}

static void print_stats(app_t *app, int64_t now, bool force) {
  if (!force && (app->stats_ms == 0 || now < app->next_stats_at))
    return;
  if (app->stats_ms == 0 && !app->stats_output)
    return;
  transport_stats_t stats = {0};
  if (!transport_get_stats(app->transport, &stats))
    return;
  if (app->stats_output) {
    fprintf(app->stats_output,
            "%" PRId64 "\t%s\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\n",
            now - app->started_at, app->node_id, app->sent_records,
            app->received_records, app->received_bytes, stats.track_ends_sent,
            stats.track_ends_received, stats.recovery_checkpoints_sent,
            stats.recovery_checkpoints_received);
    fflush(app->stats_output);
  } else {
    fprintf(stderr,
            "qlinq-app: tx=%" PRIu64 " rx=%" PRIu64 " bytes=%" PRIu64
            " connections=%zu\n",
            app->sent_records, app->received_records, app->received_bytes,
            stats.active_connections);
  }
  app->next_stats_at = now + app->stats_ms;
}

static void cleanup_reorder(app_t *app) {
  for (size_t i = 0; i < APP_REORDER_OBJECTS; i++)
    free(app->reorder[i].data);
}

int main(int argc, char **argv) {
  app_t app = {.track = {.type = MOQ_TRACK_DATA,
                         .flags = MOQ_TRACK_FLAG_FEC_RATELESS,
                         .name = "qlinq-app/data"},
               .drain_ms = 1000,
               .node_id = "qlinq-app"};
  const char *bind_host = NULL;
  const char *peer_arg = NULL;
  const char *cert_file = "t/assets/server.crt";
  const char *key_file = "t/assets/server.key";
  const char *ca_file = NULL;
  const char *input_path = NULL;
  const char *output_path = NULL;
  const char *stats_path = NULL;
  uint16_t listen_port = 0;
  uint64_t idle_timeout_ms = 0;
  uint8_t simulated_loss = 0;
  size_t message_size = 1200;
  size_t max_connections = 0;
  size_t max_repair_requests = 0;
  size_t max_aggregate_repairs = 0;
  transport_repair_mode_t repair_mode = TRANSPORT_REPAIR_MODE_AUTO;
  bool verify_peer = true;
  bool allow_insecure = false;
  uint64_t parsed;

#define REQUIRE_VALUE()                                                        \
  do {                                                                         \
    if (++i >= argc)                                                           \
      goto invalid;                                                            \
  } while (0)
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0) {
      show_help(stdout, argv[0]);
      return 0;
    } else if (strcmp(argv[i], "--listen") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT16_MAX, &parsed) || parsed == 0)
        goto invalid;
      listen_port = (uint16_t)parsed;
    } else if (strcmp(argv[i], "--peer") == 0) {
      REQUIRE_VALUE();
      peer_arg = argv[i];
    } else if (strcmp(argv[i], "--bind") == 0) {
      REQUIRE_VALUE();
      bind_host = argv[i];
    } else if (strcmp(argv[i], "--cert") == 0) {
      REQUIRE_VALUE();
      cert_file = argv[i];
    } else if (strcmp(argv[i], "--key") == 0) {
      REQUIRE_VALUE();
      key_file = argv[i];
    } else if (strcmp(argv[i], "--ca") == 0) {
      REQUIRE_VALUE();
      ca_file = argv[i];
    } else if (strcmp(argv[i], "--auth-token") == 0) {
      REQUIRE_VALUE();
      app.auth_token = (const uint8_t *)argv[i];
    } else if (strcmp(argv[i], "--insecure-no-verify") == 0) {
      verify_peer = false;
      allow_insecure = true;
    } else if (strcmp(argv[i], "--idle-timeout-ms") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT64_MAX, &idle_timeout_ms) ||
          idle_timeout_ms == 0)
        goto invalid;
    } else if (strcmp(argv[i], "--max-connections") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], TRANSPORT_HARD_MAX_CONNECTIONS, &parsed) ||
          parsed == 0)
        goto invalid;
      max_connections = (size_t)parsed;
    } else if (strcmp(argv[i], "--max-repair-requests") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT16_MAX, &parsed) || parsed == 0)
        goto invalid;
      max_repair_requests = (size_t)parsed;
    } else if (strcmp(argv[i], "--max-aggregate-repairs") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT16_MAX, &parsed) || parsed == 0)
        goto invalid;
      max_aggregate_repairs = (size_t)parsed;
    } else if (strcmp(argv[i], "--loss") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], 100, &parsed))
        goto invalid;
      simulated_loss = (uint8_t)parsed;
    } else if (strcmp(argv[i], "--track") == 0) {
      REQUIRE_VALUE();
      if (strlen(argv[i]) >= sizeof(app.track.name))
        goto invalid;
      strcpy(app.track.name, argv[i]);
    } else if (strcmp(argv[i], "--mode") == 0) {
      REQUIRE_VALUE();
      if (strcmp(argv[i], "datagram") == 0)
        app.track.flags = 0;
      else if (strcmp(argv[i], "fec") == 0)
        app.track.flags = MOQ_TRACK_FLAG_FEC_ENABLED;
      else if (strcmp(argv[i], "rateless") == 0)
        app.track.flags = MOQ_TRACK_FLAG_FEC_RATELESS;
      else if (strcmp(argv[i], "reliable") == 0)
        app.track.flags = MOQ_TRACK_FLAG_RELIABLE;
      else
        goto invalid;
    } else if (strcmp(argv[i], "--repair-mode") == 0) {
      REQUIRE_VALUE();
      if (strcmp(argv[i], "auto") == 0)
        repair_mode = TRANSPORT_REPAIR_MODE_AUTO;
      else if (strcmp(argv[i], "indexed") == 0)
        repair_mode = TRANSPORT_REPAIR_MODE_INDEXED;
      else if (strcmp(argv[i], "rateless") == 0)
        repair_mode = TRANSPORT_REPAIR_MODE_RATELESS;
      else
        goto invalid;
    } else if (strcmp(argv[i], "--input") == 0) {
      REQUIRE_VALUE();
      input_path = argv[i];
    } else if (strcmp(argv[i], "--output") == 0) {
      REQUIRE_VALUE();
      output_path = argv[i];
    } else if (strcmp(argv[i], "--message-size") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], TRANSPORT_MAX_FEC_OBJECT_SIZE, &parsed) ||
          parsed == 0)
        goto invalid;
      message_size = (size_t)parsed;
    } else if (strcmp(argv[i], "--count") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT64_MAX, &app.count_limit))
        goto invalid;
    } else if (strcmp(argv[i], "--receive-count") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT64_MAX, &app.receive_limit) ||
          app.receive_limit == 0)
        goto invalid;
    } else if (strcmp(argv[i], "--wait-subscribers") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], SIZE_MAX, &parsed))
        goto invalid;
      app.required_subscriptions = (size_t)parsed;
    } else if (strcmp(argv[i], "--interval-ms") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT32_MAX, &parsed))
        goto invalid;
      app.interval_ms = (uint32_t)parsed;
    } else if (strcmp(argv[i], "--one-shot") == 0) {
      app.one_shot = true;
    } else if (strcmp(argv[i], "--drain-ms") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT32_MAX, &parsed))
        goto invalid;
      app.drain_ms = (uint32_t)parsed;
    } else if (strcmp(argv[i], "--stats-ms") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT32_MAX, &parsed))
        goto invalid;
      app.stats_ms = (uint32_t)parsed;
    } else if (strcmp(argv[i], "--stats-file") == 0) {
      REQUIRE_VALUE();
      stats_path = argv[i];
    } else if (strcmp(argv[i], "--node-id") == 0) {
      REQUIRE_VALUE();
      if (!argv[i][0] || strchr(argv[i], '\t') || strchr(argv[i], '\n'))
        goto invalid;
      app.node_id = argv[i];
    } else if (strcmp(argv[i], "--verbose") == 0) {
      app.verbose = true;
    } else {
      goto invalid;
    }
  }
#undef REQUIRE_VALUE

  if ((listen_port == 0) == (peer_arg == NULL) ||
      (!input_path && !output_path) || (app.one_shot && !input_path) ||
      !app.auth_token || !app.auth_token[0])
    goto invalid;
  app.auth_token_len = strlen((const char *)app.auth_token);
  if (app.auth_token_len > UINT16_MAX ||
      ((app.track.flags &
        (MOQ_TRACK_FLAG_FEC_ENABLED | MOQ_TRACK_FLAG_FEC_RATELESS)) != 0 &&
       message_size > TRANSPORT_MAX_FEC_RECORD_SIZE))
    goto invalid;
  app.is_server = listen_port != 0;
  if (input_path && app.required_subscriptions == 0)
    app.required_subscriptions = 1;

  if (input_path) {
    app.input = strcmp(input_path, "-") == 0 ? stdin : fopen(input_path, "rb");
    if (!app.input) {
      fprintf(stderr, "qlinq-app: unable to open input: %s\n", strerror(errno));
      app.failed = true;
      goto cleanup;
    }
  }
  if (output_path) {
    app.output =
        strcmp(output_path, "-") == 0 ? stdout : fopen(output_path, "wb");
    if (!app.output) {
      fprintf(stderr, "qlinq-app: unable to open output: %s\n",
              strerror(errno));
      app.failed = true;
      goto cleanup;
    }
  }
  if (stats_path) {
    app.stats_output = fopen(stats_path, "w");
    if (!app.stats_output) {
      fprintf(stderr, "qlinq-app: unable to open stats: %s\n", strerror(errno));
      app.failed = true;
      goto cleanup;
    }
    fprintf(app.stats_output,
            "elapsed_ms\tnode\ttx_records\trx_records\trx_bytes\t"
            "track_ends_sent\ttrack_ends_received\tcheckpoints_sent\t"
            "checkpoints_received\n");
  }
  app.message = malloc(message_size);
  if (!app.message) {
    app.failed = true;
    goto cleanup;
  }
  app.message_capacity = message_size;

  if (portable_socket_init() != 0) {
    app.failed = true;
    goto cleanup;
  }
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  char peer_host[256] = {0};
  uint16_t port = listen_port;
  if (peer_arg) {
    port = 8888;
    if (!parse_peer(peer_arg, peer_host, sizeof(peer_host), &port)) {
      app.failed = true;
      goto cleanup_sockets;
    }
  }
  transport_config_t config = {0};
  config.bind_hosts[0] =
      bind_host ? bind_host
                : (peer_arg && strchr(peer_host, ':') ? "::" : "0.0.0.0");
  config.num_bind_hosts = 1;
  if (peer_arg) {
    config.remote_hosts[0] = peer_host;
    config.num_remote_hosts = 1;
  }
  config.port = port;
  config.quic_idle_timeout_ms = idle_timeout_ms;
  config.cert_file = cert_file;
  config.key_file = key_file;
  config.ca_file = ca_file;
  config.verify_peer = verify_peer;
  config.allow_insecure_peer = allow_insecure;
  config.callback = on_event;
  config.user_data = &app;
  config.simulated_loss_rate = simulated_loss;
  config.repair_mode = repair_mode;
  config.limits.max_connections = max_connections;
  config.limits.max_repair_requests_per_second = max_repair_requests;
  config.limits.max_aggregate_repair_requests_per_second =
      max_aggregate_repairs;
  app.transport = transport_create(&config);
  if (!app.transport) {
    fprintf(stderr, "qlinq-app: unable to create transport\n");
    app.failed = true;
    goto cleanup_sockets;
  }

  app.started_at = transport_get_time_ms();
  app.next_stats_at = app.started_at + app.stats_ms;
  while (running && !app.failed) {
    int64_t now = transport_get_time_ms();
    transport_tick(app.transport);
    publish_pending(&app, now);
    finish_track(&app, now);
    print_stats(&app, now, false);

    bool send_done = !app.one_shot || (app.track_finished &&
                                       now - app.finished_at >= app.drain_ms);
    bool receive_done =
        app.receive_limit == 0 ||
        (app.received_at != 0 && now - app.received_at >= app.drain_ms);
    if ((app.one_shot || app.receive_limit != 0) && send_done && receive_done)
      break;

    struct pollfd fds[TRANSPORT_MAX_PATHS + 1];
    size_t num_fds = transport_get_poll_fds(app.transport, fds,
                                            sizeof(fds) / sizeof(fds[0]));
    size_t input_index = SIZE_MAX;
    if (app.input && !app.input_eof && app.pending_size == 0 &&
        app.subscriptions >= app.required_subscriptions &&
        num_fds < sizeof(fds) / sizeof(fds[0])) {
      input_index = num_fds;
      fds[num_fds++] =
          (struct pollfd){.fd = fileno(app.input), .events = POLLIN};
    }
    int timeout = 10;
    int64_t deadline = transport_get_first_timeout(app.transport);
    if (deadline != INT64_MAX && deadline <= now)
      timeout = 0;
    else if (deadline != INT64_MAX && deadline - now < timeout)
      timeout = (int)(deadline - now);
    int polled = num_fds ? poll(fds, num_fds, timeout) : 0;
    bool input_ready = input_index != SIZE_MAX && polled > 0 &&
                       (fds[input_index].revents & (POLLIN | POLLHUP)) != 0;
    load_input(&app, input_ready);
  }
  print_stats(&app, transport_get_time_ms(), true);

cleanup_sockets:
  if (app.transport)
    transport_destroy(app.transport);
  portable_socket_cleanup();
cleanup:
  cleanup_reorder(&app);
  free(app.message);
  if (app.input && app.input != stdin)
    fclose(app.input);
  if (app.output && app.output != stdout)
    fclose(app.output);
  if (app.stats_output)
    fclose(app.stats_output);
  return app.failed ? 1 : 0;

invalid:
  fprintf(stderr, "qlinq-app: invalid command line\n");
  show_help(stderr, argv[0]);
  return 1;
}
