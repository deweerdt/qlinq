/* transport_quicly.c */

#include "fec.h"
#include "ifmon.h"
#include "pathflow.h"
#include "portable_sockets.h"
#include "transport.h"
#include "transport_config.h"
#include "transport_egress.h"
#include "transport_fec_state.h"
#include "transport_internal.h"
#include "transport_memory.h"
#include "transport_paths.h"
#include "transport_protocol.h"
#include "transport_publish.h"
#include "transport_repair.h"
#include "transport_scheduler.h"
#include "transport_stream.h"
#include "transport_subscriptions.h"
#include "transport_tls.h"
#include "transport_tracks.h"
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

uint64_t transport_get_time_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

void transport_release_assembler(transport_t *t, frame_assembler_t *assembler) {
  if (!t || !assembler)
    return;
  size_t bytes = transport_assembler_capacity_bytes(assembler);
  if (bytes <= t->assembler_memory_bytes)
    t->assembler_memory_bytes -= bytes;
  else
    t->assembler_memory_bytes = 0;
  transport_assembler_release(assembler);
}

bool transport_grow_assembler(transport_t *t, frame_assembler_t *assembler,
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
  if (used_without_old > t->limits.max_assembler_memory_bytes ||
      new_bytes > t->limits.max_assembler_memory_bytes - used_without_old) {
    t->stats.resource_limit_errors++;
    return false;
  }
  if (!transport_assembler_grow(assembler, symbols, symbol_size))
    return false;
  t->assembler_memory_bytes =
      used_without_old + transport_assembler_capacity_bytes(assembler);
  return true;
}

bool transport_owner_ok(transport_t *t) {
  if (!t)
    return false;
  if (pthread_equal(t->owner_thread, pthread_self()))
    return true;
  atomic_fetch_add_explicit(&t->cross_thread_violations, 1,
                            memory_order_relaxed);
  return false;
}

void transport_emit_event(transport_t *t, const transport_event_t *event) {
  if (!t || !event)
    return;
  t->callback_depth++;
  t->stats.events_emitted++;
  t->callback(t->user_data, event);
  t->callback_depth--;
}

static bool transport_has_connection(const transport_t *t,
                                     const transport_conn_t *conn);

static void accumulate_egress_stats(transport_t *t,
                                    const transport_egress_t *egress,
                                    bool dropping_pending) {
  if (!t || !egress)
    return;
  t->stats.udp_packets_sent += egress->packets_sent;
  t->stats.udp_bytes_sent += egress->bytes_sent;
  t->stats.udp_would_block += egress->would_block;
  t->stats.udp_send_errors += egress->send_errors;
  t->stats.egress_packets_queued += egress->packets_queued;
  t->stats.egress_bytes_queued += egress->bytes_queued;
  t->stats.egress_packets_dropped +=
      egress->packets_dropped + (dropping_pending ? egress->count : 0U);
  if (egress->peak_count > t->stats.egress_peak_packets)
    t->stats.egress_peak_packets = egress->peak_count;
  if (egress->peak_bytes > t->stats.egress_peak_bytes)
    t->stats.egress_peak_bytes = egress->peak_bytes;
}

bool transport_queue_datagram(transport_conn_t *conn, size_t path_index,
                              ptls_iovec_t datagram) {
  quicly_path_stats_t path_stats;
  if (!conn || !conn->quic || path_index >= TRANSPORT_MAX_QUIC_PATHS ||
      quicly_get_path_stats(conn->quic, path_index, &path_stats) != 0 ||
      conn->queued_datagrams[path_index] >= QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY)
    return false;
  quicly_send_datagram_frames_path(conn->quic, path_index, &datagram, 1);
  conn->queued_datagrams[path_index]++;
  return true;
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

  transport_limits_t limits;
  char limits_error[160];
  if (!transport_limits_resolve(&config->limits, &limits, limits_error,
                                sizeof(limits_error))) {
    fprintf(stderr, "transport: invalid limits: %s\n", limits_error);
    return NULL;
  }

  transport_t *t = calloc(1, sizeof(transport_t));
  if (!t) {
    fprintf(stderr, "transport: failed to allocate transport state\n");
    return NULL;
  }

  for (size_t i = 0; i < TRANSPORT_MAX_PATHS; i++)
    t->fds[i] = -1;
  t->owner_thread = pthread_self();
  atomic_init(&t->cross_thread_violations, 0);
  t->limits = limits;
  if (config->repair_mode != TRANSPORT_REPAIR_MODE_AUTO &&
      config->repair_mode != TRANSPORT_REPAIR_MODE_INDEXED &&
      config->repair_mode != TRANSPORT_REPAIR_MODE_RATELESS) {
    free(t);
    return NULL;
  }
  t->repair_mode = config->repair_mode;
  t->next_conn_id = 1;
  t->ifmon_pipe[0] = -1;
  t->ifmon_pipe[1] = -1;

  t->conns = calloc(t->limits.max_connections, sizeof(*t->conns));
  if (!t->conns) {
    free(t);
    return NULL;
  }
  for (size_t i = 0; i < config->num_bind_hosts; i++) {
    if (!transport_egress_init(&t->egress[i],
                               t->limits.max_egress_packets_per_socket,
                               t->limits.max_egress_bytes_per_socket)) {
      transport_destroy(t);
      return NULL;
    }
  }

  if (!transport_arena_init(&t->arena, 16U * 1024U * 1024U)) {
    fprintf(stderr, "transport: failed to allocate packet arena\n");
    for (size_t i = 0; i < TRANSPORT_MAX_PATHS; i++)
      transport_egress_destroy(&t->egress[i]);
    free(t->conns);
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

  transport_protocol_setup(t);
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
  t->quic_ctx.initial_egress_max_udp_payload_size =
      t->limits.max_udp_payload_size;
  t->quic_ctx.transport_params.max_datagram_frame_size =
      t->limits.max_udp_payload_size;
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
    conn->id = t->next_conn_id++;
    if (!transport_subscriptions_init(
            &conn->subscriptions, t->limits.max_subscriptions_per_connection)) {
      free(conn);
      transport_destroy(t);
      return NULL;
    }

    int ret =
        quicly_connect(&conn->quic, &t->quic_ctx, config->remote_hosts[0],
                       (struct sockaddr *)&t->remote_addrs[0],
                       (struct sockaddr *)&t->local_addrs[0], &t->next_cid,
                       ptls_iovec_init(NULL, 0), NULL, NULL, NULL);
    if (ret != 0) {
      transport_subscriptions_destroy(&conn->subscriptions);
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
  if (!transport_owner_ok(t))
    return;
  if (t->callback_depth != 0) {
    t->stats.callback_destroy_rejections++;
    return;
  }

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
  for (size_t i = 0; i < TRANSPORT_MAX_PATHS; i++)
    transport_egress_destroy(&t->egress[i]);

  if (t->is_server) {
    for (size_t i = 0; i < t->conn_count; i++) {
      transport_conn_t *conn = t->conns[i];
      quicly_free(conn->quic);
      for (size_t a = 0; a < t->limits.max_assemblers_per_connection; a++)
        transport_release_assembler(t, &conn->assemblers[a]);
      transport_subscriptions_destroy(&conn->subscriptions);
      free(conn);
    }
  } else if (t->client_conn) {
    transport_conn_t *conn = t->client_conn;
    quicly_free(conn->quic);
    for (size_t a = 0; a < t->limits.max_assemblers_per_connection; a++)
      transport_release_assembler(t, &conn->assemblers[a]);
    transport_subscriptions_destroy(&conn->subscriptions);
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

  free(t->conns);
  free(t);
}

void transport_tick(transport_t *t) {
  if (!transport_owner_ok(t))
    return;
  if (t->tick_active) {
    t->stats.recursive_tick_rejections++;
    return;
  }
  t->tick_active = true;

  for (size_t i = 0; i < t->num_fds; i++)
    (void)transport_egress_flush(&t->egress[i], t->fds[i]);

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
      transport_object_gap_state_t *gap = &conn->object_gaps[alias];
      if (gap->pending_mask == 0 ||
          now_nack_ms - gap->detected_at_ms < QLINQ_FEC_NACK_DELAY_MS)
        continue;
      for (uint32_t bit = 0; bit < 32 && object_nack_budget > 0; bit++) {
        if ((gap->pending_mask & (1U << bit)) == 0)
          continue;
        if (transport_protocol_send_nack(
                conn, (uint8_t)alias, gap->group_id, gap->pending_base + bit,
                NULL, 0, true)) {
          /* Keep the gap pending until a symbol arrives. A NACK being queued
           * does not guarantee that its repair will be admitted or delivered. */
          gap->detected_at_ms = now_nack_ms;
          object_nack_budget--;
        } else {
          break;
        }
      }
    }

    for (size_t i = 0; i < t->limits.max_assemblers_per_connection; i++) {
      frame_assembler_t *asm_slot = &conn->assemblers[i];
      if (asm_slot->total_symbols == 0)
        continue;

      if (now_nack_ms - asm_slot->last_activity_time_ms >=
          QLINQ_FEC_ASSEMBLER_TIMEOUT_MS) {
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
          t->stats.fec_objects_lost++;
          transport_emit_event(t, &ev);
        }
        transport_release_assembler(t, asm_slot);
        continue;
      }

      if (!asm_slot->decoded &&
          now_nack_ms - asm_slot->first_symbol_time_ms >=
              QLINQ_FEC_NACK_DELAY_MS &&
          (!asm_slot->nack_sent || now_nack_ms - asm_slot->last_nack_time_ms >=
                                       QLINQ_FEC_NACK_DELAY_MS)) {
        moq_track_id_t resolved_track;
        if (transport_subscriptions_find_by_alias(&conn->subscriptions,
                                                  asm_slot->track_id,
                                                  &resolved_track) != 0 ||
            !(resolved_track.flags & MOQ_TRACK_FLAG_FEC_RATELESS))
          continue; /* Fixed RS-FEC does not send NACKs */
        transport_repair_mode_t repair_mode =
            transport_get_effective_repair_mode(t, conn, &resolved_track);
        uint16_t missing_count = 0;
        const uint16_t *missing = NULL;
        if (repair_mode == TRANSPORT_REPAIR_MODE_RATELESS) {
          missing_count = asm_slot->received_count < asm_slot->data_symbols
                              ? (uint16_t)(asm_slot->data_symbols -
                                           asm_slot->received_count)
                              : 1U;
          if (missing_count > TRANSPORT_REPAIR_MAX_SYMBOLS)
            missing_count = TRANSPORT_REPAIR_MAX_SYMBOLS;
        } else {
          for (uint16_t s = 0; s < asm_slot->total_symbols; s++) {
            if (!asm_slot->received_mask[s] &&
                missing_count < TRANSPORT_REPAIR_MAX_SYMBOLS) {
              asm_slot->missing_indices[missing_count++] = s;
            }
          }
          missing = asm_slot->missing_indices;
        }
        if (missing_count > 0) {
          if (transport_protocol_send_nack(
                  conn, asm_slot->track_id, asm_slot->group_id,
                  asm_slot->object_id, missing, missing_count, false)) {
            asm_slot->nack_sent = true;
            asm_slot->last_nack_time_ms = now_nack_ms;
          }
        }
      }
    }
  }

  /* Check for FEC grouping buffer timeout (3 milliseconds) */
  if (t->fec_buf_len > 0) {
    uint64_t now = ptls_get_time.cb(&ptls_get_time);
    if ((now - t->fec_first_pkt_time) >= 3) {
      (void)transport_publish_flush_grouped(t);
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

              if (!transport_egress_init(
                      &t->egress[t->num_fds],
                      t->limits.max_egress_packets_per_socket,
                      t->limits.max_egress_bytes_per_socket)) {
                CLOSE_SOCKET(fd);
                continue;
              }

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
            accumulate_egress_stats(t, &t->egress[i], true);
            transport_egress_destroy(&t->egress[i]);
            CLOSE_SOCKET(t->fds[i]);
            /* remove from array */
            for (size_t j = i; j < t->num_fds - 1; j++) {
              t->fds[j] = t->fds[j + 1];
              t->local_addrs[j] = t->local_addrs[j + 1];
              t->local_addrs_len[j] = t->local_addrs_len[j + 1];
              t->local_ifindices[j] = t->local_ifindices[j + 1];
              t->egress[j] = t->egress[j + 1];
            }
            t->num_fds--;
            memset(&t->egress[t->num_fds], 0, sizeof(t->egress[t->num_fds]));
            fprintf(stderr, "ifmon: removed socket for local IP\n");
            break;
          }
        }
      }
    }
  }

  size_t receive_budget = t->limits.max_packets_per_tick;
  for (size_t fd_idx = 0; fd_idx < t->num_fds && receive_budget > 0; fd_idx++) {
    while (receive_budget > 0) {
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
      receive_budget--;

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
          if (!target && t->conn_count < t->limits.max_connections) {
            quicly_conn_t *new_quic = NULL;
            int accept_res =
                quicly_accept(&new_quic, &t->quic_ctx,
                              (struct sockaddr *)&t->local_addrs[fd_idx], psa,
                              &decoded, NULL, &t->next_cid, NULL, NULL);
            if (accept_res == 0 && new_quic) {
              target = calloc(1, sizeof(transport_conn_t));
              if (!target) {
                quicly_free(new_quic);
                t->stats.connections_rejected++;
                continue;
              }
              target->transport = t;
              target->quic = new_quic;
              target->id = t->next_conn_id++;
              if (!transport_subscriptions_init(
                      &target->subscriptions,
                      t->limits.max_subscriptions_per_connection)) {
                quicly_free(new_quic);
                free(target);
                target = NULL;
                t->stats.connections_rejected++;
                continue;
              }
              *quicly_get_data(new_quic) = target;
              t->conns[t->conn_count++] = target;
              t->stats.connections_accepted++;
            }
          } else if (!target) {
            t->stats.connections_rejected++;
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

    if (!conn->quic_ready && quicly_connection_is_ready(conn->quic)) {
      conn->quic_ready = true;
    }
    if (conn->quic_ready)
      (void)transport_protocol_send_hello(conn);
    transport_protocol_maybe_emit_connected(conn);

    while (1) {
      bool egress_has_room = true;
      for (size_t p = 0; p < t->num_fds; p++) {
        if (!transport_egress_can_accept(&t->egress[p], 64U, 64U * 1500U)) {
          egress_has_room = false;
          break;
        }
      }
      if (!egress_has_room)
        break;

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

        size_t out_fd_index = 0;
        if (src.sa.sa_family == AF_INET) {
          struct sockaddr_in *src_in = (struct sockaddr_in *)&src.sa;
          for (size_t k = 0; k < t->num_fds; k++) {
            if (t->local_addrs[k].ss_family == AF_INET) {
              struct sockaddr_in *loc =
                  (struct sockaddr_in *)&t->local_addrs[k];
              if (loc->sin_addr.s_addr == src_in->sin_addr.s_addr) {
                out_fd_index = k;
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
                out_fd_index = k;
                break;
              }
            }
          }
        }

        if (!transport_egress_submit(
                &t->egress[out_fd_index], t->fds[out_fd_index], &dest.sa,
                quicly_get_socklen(&dest.sa), dgrams, num_dgrams))
          fprintf(stderr, "transport: UDP egress queue exhausted\n");
      } else if (send_res == QUICLY_ERROR_FREE_CONNECTION) {
        fprintf(stderr, "Connection %p freed (is_server=%d)\n", conn,
                t->is_server);
        transport_event_t ev = {.type = TRANSPORT_EVENT_DISCONNECTED,
                                .conn = conn};
        transport_emit_event(t, &ev);
        t->stats.connections_closed++;

        quicly_free(conn->quic);
        for (size_t a = 0; a < t->limits.max_assemblers_per_connection; a++)
          transport_release_assembler(t, &conn->assemblers[a]);
        transport_subscriptions_destroy(&conn->subscriptions);
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
  t->tick_active = false;
}

bool transport_subscribe(transport_t *t, moq_track_id_t track_id) {
  if (!transport_owner_ok(t) || !transport_track_id_valid(&track_id))
    return false;

  if (t->is_server) {
    for (size_t i = 0; i < t->conn_count; i++) {
      transport_conn_t *conn = t->conns[i];
      if (!conn || !conn->protocol_ready || !conn->authenticated ||
          !conn->stream || !quicly_sendstate_is_open(&conn->stream->sendstate))
        continue;

      uint8_t alias;
      if (transport_subscriptions_find_alias(&conn->subscriptions, &track_id,
                                             &alias) != 0) {
        if (transport_subscriptions_count(&conn->subscriptions) >=
            conn->negotiated_limits.max_subscriptions_per_connection)
          return false;
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

  if (!t->client_conn || !t->client_conn->protocol_ready ||
      !t->client_conn->authenticated || !t->client_conn->stream ||
      !quicly_sendstate_is_open(&t->client_conn->stream->sendstate)) {
    return false;
  }

  uint8_t alias;
  if (transport_subscriptions_find_alias(&t->client_conn->subscriptions,
                                         &track_id, &alias) != 0) {
    if (transport_subscriptions_count(&t->client_conn->subscriptions) >=
        t->client_conn->negotiated_limits.max_subscriptions_per_connection)
      return false;
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
  if (!transport_owner_ok(t) || !transport_track_id_valid(&track_id) ||
      t->is_server || !t->client_conn || !t->client_conn->protocol_ready ||
      !t->client_conn->authenticated || !t->client_conn->stream ||
      !quicly_sendstate_is_open(&t->client_conn->stream->sendstate))
    return false;

  return transport_stream_write_track_frame(
      t->client_conn->stream, QLINQ_WIRE_KEYFRAME_REQUEST, 0, &track_id);
}

bool transport_send_unicast(transport_t *t, transport_conn_t *conn,
                            const void *data, size_t size) {
  if (!transport_owner_ok(t) || size > t->limits.max_reliable_object_size ||
      (size > 0 && !data))
    return false;
  if (!transport_has_connection(t, conn) || !conn->protocol_ready ||
      !conn->stream || !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;

  return transport_stream_write_frame(conn->stream, QLINQ_WIRE_UNICAST, data,
                                      size);
}

void transport_close_conn(transport_t *t, transport_conn_t *conn) {
  if (!transport_owner_ok(t))
    return;
  if (transport_has_connection(t, conn) && conn->quic) {
    quicly_close(conn->quic, 0, "");
  }
}

bool transport_send_auth(transport_t *t, transport_conn_t *conn,
                         const uint8_t *token, size_t token_len) {
  if (!transport_owner_ok(t))
    return false;
  if (!transport_has_connection(t, conn) || !conn->protocol_ready ||
      !conn->stream || !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;
  if (token_len > 65535 || (token_len > 0 && !token))
    return false;

  return transport_stream_write_frame(conn->stream, QLINQ_WIRE_AUTH_REQUEST,
                                      token, token_len);
}

bool transport_respond_auth(transport_t *t, transport_conn_t *conn,
                            bool success) {
  if (!transport_owner_ok(t))
    return false;
  if (!transport_has_connection(t, conn) || !conn->protocol_ready ||
      !conn->stream || !quicly_sendstate_is_open(&conn->stream->sendstate))
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
  if (!transport_owner_ok(t))
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

static bool transport_has_connection(const transport_t *t,
                                     const transport_conn_t *conn) {
  if (!t || !conn)
    return false;
  if (!t->is_server)
    return t->client_conn == conn;
  for (size_t i = 0; i < t->conn_count; i++) {
    if (t->conns[i] == conn)
      return true;
  }
  return false;
}

bool transport_get_stats(transport_t *t, transport_stats_t *stats) {
  if (!transport_owner_ok(t) || !stats)
    return false;
  *stats = t->stats;
  stats->api_thread_violations +=
      atomic_load_explicit(&t->cross_thread_violations, memory_order_relaxed);
  stats->active_connections =
      t->is_server ? t->conn_count : (t->client_conn ? 1U : 0U);
  stats->assembler_memory_bytes = t->assembler_memory_bytes;
  for (size_t i = 0; i < t->num_fds; i++) {
    const transport_egress_t *egress = &t->egress[i];
    stats->udp_packets_sent += egress->packets_sent;
    stats->udp_bytes_sent += egress->bytes_sent;
    stats->udp_would_block += egress->would_block;
    stats->udp_send_errors += egress->send_errors;
    stats->egress_packets_queued += egress->packets_queued;
    stats->egress_bytes_queued += egress->bytes_queued;
    stats->egress_packets_dropped += egress->packets_dropped;
    stats->egress_current_packets += egress->count;
    stats->egress_current_bytes += egress->bytes;
    if (egress->peak_count > stats->egress_peak_packets)
      stats->egress_peak_packets = egress->peak_count;
    if (egress->peak_bytes > stats->egress_peak_bytes)
      stats->egress_peak_bytes = egress->peak_bytes;
  }
  return true;
}

bool transport_get_conn_stats(transport_t *t, transport_conn_t *conn,
                              transport_conn_stats_t *stats) {
  if (!transport_owner_ok(t) || !stats || !transport_has_connection(t, conn))
    return false;
  memset(stats, 0, sizeof(*stats));
  stats->id = conn->id;
  stats->quic_ready = conn->quic_ready;
  stats->protocol_ready = conn->protocol_ready;
  stats->authenticated = conn->authenticated;
  stats->subscriptions = transport_subscriptions_count(&conn->subscriptions);
  stats->peer_capabilities = conn->peer_capabilities;
  stats->negotiated_limits = conn->negotiated_limits;
  stats->stream_frames_received = conn->stream_frames_received;
  stats->datagrams_received = conn->datagrams_received;
  stats->malformed_datagrams = conn->malformed_datagrams;
  return true;
}

uint32_t transport_get_conn_id(transport_t *t, transport_conn_t *conn) {
  return transport_owner_ok(t) && transport_has_connection(t, conn) ? conn->id
                                                                    : 0;
}

transport_repair_mode_t
transport_get_effective_repair_mode(transport_t *t, transport_conn_t *conn,
                                    const moq_track_id_t *track_id) {
  if (!transport_owner_ok(t) || !transport_has_connection(t, conn) ||
      !transport_track_id_valid(track_id))
    return TRANSPORT_REPAIR_MODE_INDEXED;
  return t->repair_mode != TRANSPORT_REPAIR_MODE_INDEXED &&
                 (track_id->flags & MOQ_TRACK_FLAG_FEC_RATELESS) != 0 &&
                 (conn->peer_capabilities & QLINQ_WIRE_CAP_RATELESS_REPAIR) != 0
             ? TRANSPORT_REPAIR_MODE_RATELESS
             : TRANSPORT_REPAIR_MODE_INDEXED;
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
  if (!transport_owner_ok(t) || !stats || path_idx >= t->num_fds)
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
  if (!transport_owner_ok(t) || t->ifmon_pipe[1] < 0)
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
  if (!transport_owner_ok(t) || path_idx >= t->num_fds ||
      packets_per_second == 0 || latency_ms < 0.0 || loss_rate < 0.0 ||
      loss_rate > 1.0)
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
  if (!t || !transport_owner_ok((transport_t *)t))
    return 0;
  size_t udp_payload_size = t->limits.max_udp_payload_size;
  size_t active_count = t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
  for (size_t i = 0; i < active_count; i++) {
    const transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
    if (conn && conn->protocol_ready &&
        conn->negotiated_limits.max_udp_payload_size < udp_payload_size)
      udp_payload_size = conn->negotiated_limits.max_udp_payload_size;
  }
  size_t symbol_size = udp_payload_size > 80U ? udp_payload_size - 80U : 0U;
  return symbol_size < 1000 ? 1000 : symbol_size;
}

bool transport_is_track_ready(transport_t *t, const moq_track_id_t *track_id) {
  if (!transport_owner_ok(t) || !transport_track_id_valid(track_id))
    return false;

  for (size_t i = 0; i < t->num_fds; i++) {
    const transport_egress_t *egress = &t->egress[i];
    if (egress->count >= egress->capacity * 3U / 4U ||
        egress->bytes >= egress->max_bytes * 3U / 4U)
      return false;
  }

  transport_track_profile_t profile = transport_track_profile(track_id);

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
            QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY * 3 / 4) {
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
  if (!transport_owner_ok(t))
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
  if (!transport_owner_ok(t) || !fds)
    return 0;

  size_t count = 0;
  for (size_t i = 0; i < t->num_fds && count < max_fds; i++) {
    if (t->fds[i] >= 0) {
      fds[count].fd = t->fds[i];
      fds[count].events = POLLIN;
      if (t->egress[i].count > 0)
        fds[count].events |= POLLOUT;
      fds[count].revents = 0;
      count++;
    }
  }
  return count;
}
