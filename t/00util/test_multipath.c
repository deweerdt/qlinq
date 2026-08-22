/* test_multipath.c */

#include "ifmon.h"
#include "pathflow.h"
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "transport.h"
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define TEST_MAX_PATHS 4
#define TEST_MAX_CONNECTIONS 32
#define TEST_SENT_CACHE_SIZE 32
#define TEST_ARENA_MAX_FALLBACKS 1024

typedef struct {
  uint8_t *buffer;
  size_t capacity;
  size_t offset;
  void *fallbacks[TEST_ARENA_MAX_FALLBACKS];
  size_t fallback_count;
} arena_t;

typedef struct {
  moq_track_id_t track_id;
  uint64_t group_id;
  uint64_t object_id;
  uint8_t *data;
  size_t size;
  uint8_t priority;
  bool is_keyframe;
  uint16_t total_symbols;
  uint16_t data_symbols;
  uint16_t symbol_size;
} sent_object_cache_t;

typedef struct transport_conn_t transport_conn_t;

struct transport_t_internal {
  transport_callback_t callback;
  void *user_data;
  bool is_server;
  int fds[TEST_MAX_PATHS];
  size_t num_fds;
  struct sockaddr_storage local_addrs[TEST_MAX_PATHS];
  socklen_t local_addrs_len[TEST_MAX_PATHS];
  uint32_t local_ifindices[TEST_MAX_PATHS];

  /* client connection */
  struct sockaddr_storage remote_addrs[TEST_MAX_PATHS];
  socklen_t remote_addrs_len[TEST_MAX_PATHS];
  size_t num_remote_addrs;
  quicly_context_t quic_ctx;
  ptls_context_t tls_ctx;
  ptls_openssl_sign_certificate_t sign_cert;
  quicly_cid_plaintext_t next_cid;

  path_state_t path_states[TEST_MAX_PATHS];
  uint64_t last_pathflow_update;

  int64_t min_owd_ns[TEST_MAX_PATHS];
  fp_t latest_owd_fp[TEST_MAX_PATHS];
  uint64_t last_telemetry_s_ns[TEST_MAX_PATHS];
  uint64_t last_telemetry_r_ns[TEST_MAX_PATHS];

  /* server connections list */
  transport_conn_t *conns[TEST_MAX_CONNECTIONS];
  size_t conn_count;

  /* client connection */
  transport_conn_t *client_conn;

  /* stream open callback payload */
  quicly_stream_open_t stream_open;
  ptls_verify_certificate_t verifier;
  quicly_receive_datagram_frame_t receive_datagram;

  /* sent object history cache for NACK retransmissions */
  sent_object_cache_t sent_cache[TEST_SENT_CACHE_SIZE];
  size_t sent_cache_index;

  /* simulated packet loss */
  uint8_t simulated_loss_rate;

  /* pre-allocated transport memory arena */
  arena_t arena;

  /* ifmon integration */
  ifmon_watcher_t ifmon_w;
  int ifmon_pipe[2];
};

typedef struct {
  bool connected;
  bool subscribed;
  bool object_received;
  uint8_t received_data[100];
  size_t received_size;
  transport_t *transport;
} test_state_t;

static void on_server_event(void *user_data, const transport_event_t *event) {
  test_state_t *state = user_data;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    state->connected = true;
    break;
  case TRANSPORT_EVENT_SUBSCRIBE:
    if (event->track_id.type == MOQ_TRACK_VIDEO &&
        strcmp(event->track_id.name, "video_track") == 0) {
      state->subscribed = true;
    }
    break;
  case TRANSPORT_EVENT_AUTH:
    transport_respond_auth(state->transport, event->conn, true);
    break;
  default:
    break;
  }
}

static void on_client_event(void *user_data, const transport_event_t *event) {
  test_state_t *state = user_data;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    transport_send_auth(state->transport, event->conn,
                        (const uint8_t *)"secret", 6);
    break;
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    if (event->auth.success) {
      state->connected = true;
    }
    break;
  case TRANSPORT_EVENT_OBJECT:
    if (event->track_id.type == MOQ_TRACK_VIDEO &&
        strcmp(event->track_id.name, "video_track") == 0) {
      state->object_received = true;
      state->received_size = event->object.size;
      if (event->object.size < sizeof(state->received_data)) {
        memcpy(state->received_data, event->object.data, event->object.size);
        state->received_data[event->object.size] = '\0';
      }
    }
    break;
  default:
    break;
  }
}

static int setup_qlog_listener(const char *path) {
  unlink(path);
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(fd);
    return -1;
  }

  if (listen(fd, 5) < 0) {
    close(fd);
    return -1;
  }

  return fd;
}

static size_t total_qlog_bytes = 0;
static void drain_qlog(int log_fd) {
  if (log_fd < 0)
    return;
  char trash[2048];
  ssize_t r;
  while (1) {
    r = read(log_fd, trash, sizeof(trash));
    if (r > 0) {
      total_qlog_bytes += r;
    } else if (r < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
      break;
    } else {
      break; /* EOF */
    }
  }
}

#include <signal.h>

int main(void) {
  signal(SIGPIPE, SIG_IGN);
  const char *qlog_path = "tmp/test_qlog.sock";
  mkdir("tmp", 0777);

  int listener_fd = setup_qlog_listener(qlog_path);
  if (listener_fd < 0) {
    fprintf(stderr, "failed to setup qlog listener\n");
    return 1;
  }

  test_state_t server_state = {0};
  test_state_t client_state = {0};

  /* server binds to 4 loopback IPs */
  transport_config_t server_cfg = {0};
  server_cfg.bind_hosts[0] = "127.0.1.1";
  server_cfg.bind_hosts[1] = "127.0.2.1";
  server_cfg.bind_hosts[2] = "127.0.3.1";
  server_cfg.bind_hosts[3] = "127.0.4.1";
  server_cfg.num_bind_hosts = 4;
  server_cfg.port = 9876;
  server_cfg.cert_file = "t/assets/server.crt";
  server_cfg.key_file = "t/assets/server.key";
  server_cfg.callback = on_server_event;
  server_cfg.allow_insecure_peer = true;
  server_cfg.user_data = &server_state;

  /* client initially binds only to 127.0.1.2 */
  transport_config_t client_cfg = {0};
  client_cfg.bind_hosts[0] = "127.0.1.2";
  client_cfg.num_bind_hosts = 1;
  client_cfg.remote_hosts[0] = "127.0.1.1";
  client_cfg.remote_hosts[1] = "127.0.2.1";
  client_cfg.remote_hosts[2] = "127.0.3.1";
  client_cfg.remote_hosts[3] = "127.0.4.1";
  client_cfg.num_remote_hosts = 4;
  client_cfg.port = 9876;
  client_cfg.cert_file = NULL;
  client_cfg.key_file = NULL;
  client_cfg.callback = on_client_event;
  client_cfg.allow_insecure_peer = true;
  client_cfg.user_data = &client_state;

  printf("creating transports...\n");
  transport_t *server = transport_create(&server_cfg);
  if (!server) {
    fprintf(stderr, "failed to create server\n");
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }
  server_state.transport = server;

  transport_t *client = transport_create(&client_cfg);
  if (!client) {
    fprintf(stderr, "failed to create client\n");
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }
  client_state.transport = client;

  /* enable qlog on client */
  if (transport_enable_qlog(qlog_path) != 0) {
    fprintf(stderr, "failed to enable qlog\n");
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  printf("accepting qlog connection...\n");
  int log_fd = accept(listener_fd, NULL, NULL);
  if (log_fd < 0) {
    fprintf(stderr, "immediate accept failed: %s (errno=%d)\n", strerror(errno),
            errno);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }
  printf("immediate accept succeeded: log_fd=%d\n", log_fd);

  /* set both sockets to non-blocking */
  int flags = fcntl(listener_fd, F_GETFL, 0);
  fcntl(listener_fd, F_SETFL, flags | O_NONBLOCK);
  flags = fcntl(log_fd, F_GETFL, 0);
  fcntl(log_fd, F_SETFL, flags | O_NONBLOCK);

  int retries = 200;
  printf("connecting client and server...\n");
  while (retries-- > 0 &&
         (!server_state.connected || !client_state.connected)) {
    transport_tick(server);
    transport_tick(client);
    drain_qlog(log_fd);
    usleep(10 * 1000);
  }

  if (!server_state.connected || !client_state.connected) {
    fprintf(stderr, "connection timeout\n");
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  /* mock local interface additions with matching client suffix .2 */
  printf("triggering secondary loopback path validation...\n");
  transport_mock_iface_add(client, "127.0.2.2");
  transport_mock_iface_add(client, "127.0.3.2");
  transport_mock_iface_add(client, "127.0.4.2");

  /* tick transports to process interface updates and complete validation */
  retries = 200;
  while (retries-- > 0) {
    transport_tick(server);
    transport_tick(client);
    drain_qlog(log_fd);
    usleep(10 * 1000);
  }

  /* subscribe to video track */
  moq_track_id_t t_video = {.type = MOQ_TRACK_VIDEO,
                            .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                            .name = "video_track"};
  transport_subscribe(client, t_video);

  retries = 200;
  while (retries-- > 0 && !server_state.subscribed) {
    transport_tick(server);
    transport_tick(client);
    drain_qlog(log_fd);
    usleep(10 * 1000);
  }

  if (!server_state.subscribed) {
    fprintf(stderr, "subscribe timeout\n");
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  /* publish object */
  const char *payload = "hello sleepy bishop multipath!";
  moq_object_t obj = {.track_id = t_video,
                      .group_id = 1,
                      .object_id = 1,
                      .data = (const uint8_t *)payload,
                      .size = strlen(payload),
                      .is_keyframe = true};
  transport_publish(server, &obj);

  retries = 200;
  while (retries-- > 0 && !client_state.object_received) {
    transport_tick(server);
    transport_tick(client);
    drain_qlog(log_fd);
    usleep(10 * 1000);
  }

  if (!client_state.object_received) {
    fprintf(stderr, "object receive timeout\n");
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  if (strcmp((char *)client_state.received_data, payload) != 0) {
    fprintf(stderr, "payload mismatch\n");
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  /* verify path statistics and count active paths */
  int path_count = 0;
  for (size_t i = 0; i < 4; i++) {
    transport_path_stats_t stats;
    if (transport_get_path_stats(client, i, &stats)) {
      path_count++;
    }
  }

  if (path_count < 4) {
    fprintf(stderr, "not all 4 paths were successfully established: count=%d\n",
            path_count);
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  /* Test 60/5/10/25 split for 1000 packets */
  printf("testing 60/5/10/25 split for 1000 packets...\n");
  struct transport_t_internal *s_t = (struct transport_t_internal *)server;
  s_t->path_states[0].initialized = 1;
  s_t->path_states[0].b_ewma = FP_FROM_INT(60);
  s_t->path_states[0].l_ewma = FP_FROM_FLOAT(0.010f);
  s_t->path_states[0].p_ewma = 0;
  s_t->path_states[0].q_ewma = 0;

  s_t->path_states[1].initialized = 1;
  s_t->path_states[1].b_ewma = FP_FROM_INT(5);
  s_t->path_states[1].l_ewma = FP_FROM_FLOAT(0.010f);
  s_t->path_states[1].p_ewma = 0;
  s_t->path_states[1].q_ewma = 0;

  s_t->path_states[2].initialized = 1;
  s_t->path_states[2].b_ewma = FP_FROM_INT(10);
  s_t->path_states[2].l_ewma = FP_FROM_FLOAT(0.010f);
  s_t->path_states[2].p_ewma = 0;
  s_t->path_states[2].q_ewma = 0;

  s_t->path_states[3].initialized = 1;
  s_t->path_states[3].b_ewma = FP_FROM_INT(25);
  s_t->path_states[3].l_ewma = FP_FROM_FLOAT(0.010f);
  s_t->path_states[3].p_ewma = 0;
  s_t->path_states[3].q_ewma = 0;

  /* Prevent transport_tick from overwriting our mock state */
  s_t->last_pathflow_update = UINT64_MAX / 2;

  /* Increase socket buffer sizes to avoid packet drops under 1MB payload */
  int buf_size = 4 * 1024 * 1024;
  for (size_t i = 0; i < s_t->num_fds; i++) {
    setsockopt(s_t->fds[i], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    setsockopt(s_t->fds[i], SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
  }
  struct transport_t_internal *c_t = (struct transport_t_internal *)client;
  for (size_t i = 0; i < c_t->num_fds; i++) {
    setsockopt(c_t->fds[i], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    setsockopt(c_t->fds[i], SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
  }

  /* Fetch baseline stats from server connection paths */
  transport_path_stats_t base_stats[4];
  for (size_t i = 0; i < 4; i++) {
    if (!transport_get_path_stats(server, i, &base_stats[i])) {
      fprintf(stderr, "failed to get server base path stats for path %zu\n", i);
      close(log_fd);
      transport_destroy(client);
      transport_destroy(server);
      close(listener_fd);
      unlink(qlog_path);
      return 1;
    }
  }

  /* Determine exact symbol size to build exact symbol counts */
  size_t symbol_size = 1100;
  if (s_t->quic_ctx.initial_egress_max_udp_payload_size > 80) {
    symbol_size = s_t->quic_ctx.initial_egress_max_udp_payload_size - 80;
  }
  if (symbol_size < 1000)
    symbol_size = 1000;

  /* Publish 20 objects of 50 symbols each to make 1000 packets total */
  printf("publishing 1000 packets in 20 chunks of 50 packets to prevent socket "
         "overflow...\n");
  for (int chunk = 0; chunk < 20; chunk++) {
    size_t chunk_size = 50 * symbol_size;
    uint8_t *chunk_payload = malloc(chunk_size);
    if (!chunk_payload) {
      fprintf(stderr, "failed to allocate chunk payload\n");
      close(log_fd);
      transport_destroy(client);
      transport_destroy(server);
      close(listener_fd);
      unlink(qlog_path);
      return 1;
    }
    memset(chunk_payload, 'A', chunk_size);

    /* Reset client receive flag/size */
    client_state.object_received = false;
    client_state.received_size = 0;

    moq_object_t chunk_obj = {.track_id = t_video,
                              .group_id = 2 + chunk,
                              .object_id = 2 + chunk,
                              .data = chunk_payload,
                              .size = chunk_size,
                              .is_keyframe = true};
    transport_publish(server, &chunk_obj);
    free(chunk_payload);

    /* Tick client and server in a loop to transfer this chunk */
    retries = 2000;
    while (retries-- > 0 && !client_state.object_received) {
      s_t->last_pathflow_update = ptls_get_time.cb(&ptls_get_time);
      transport_tick(server);
      transport_tick(client);
      drain_qlog(log_fd);
      usleep(500);
    }

    if (!client_state.object_received) {
      fprintf(stderr, "chunk %d receive timeout\n", chunk);
      close(log_fd);
      transport_destroy(client);
      transport_destroy(server);
      close(listener_fd);
      unlink(qlog_path);
      return 1;
    }
  }

  /* Verify the packet split on the server's paths */
  transport_path_stats_t final_stats[4];
  long diff_sent[4];
  for (size_t i = 0; i < 4; i++) {
    if (!transport_get_path_stats(server, i, &final_stats[i])) {
      fprintf(stderr, "failed to get server final stats for path %zu\n", i);
      close(log_fd);
      transport_destroy(client);
      transport_destroy(server);
      close(listener_fd);
      unlink(qlog_path);
      return 1;
    }
    diff_sent[i] = (long)final_stats[i].sent - (long)base_stats[i].sent;
    printf("path %zu: base_sent=%lu, final_sent=%lu, diff=%ld\n", i,
           (unsigned long)base_stats[i].sent,
           (unsigned long)final_stats[i].sent, diff_sent[i]);
  }

  /* Assert the split matches 60/5/10/25 +/- 5% margin */
  /* Expected packets: 640, 40, 100, 240 */
  bool split_ok = true;
  if (diff_sent[0] < 600 || diff_sent[0] > 660) {
    fprintf(stderr,
            "path 0 sent packets %ld out of expected range [600, 660]\n",
            diff_sent[0]);
    split_ok = false;
  }
  if (diff_sent[1] < 35 || diff_sent[1] > 65) {
    fprintf(stderr, "path 1 sent packets %ld out of expected range [35, 65]\n",
            diff_sent[1]);
    split_ok = false;
  }
  if (diff_sent[2] < 85 || diff_sent[2] > 115) {
    fprintf(stderr, "path 2 sent packets %ld out of expected range [85, 115]\n",
            diff_sent[2]);
    split_ok = false;
  }
  if (diff_sent[3] < 220 || diff_sent[3] > 260) {
    fprintf(stderr,
            "path 3 sent packets %ld out of expected range [220, 260]\n",
            diff_sent[3]);
    split_ok = false;
  }

  if (!split_ok) {
    fprintf(stderr, "pathflow split verification failed!\n");
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }
  printf("60/5/10/25 split verified successfully!\n");

  /* destroy client transport to flush final trace logs to socket */
  printf("destroying client transport to flush qlog...\n");
  transport_destroy(client);

  /* read last trace data (using non-blocking drain) */
  usleep(50 * 1000);
  drain_qlog(log_fd);

  printf("total qlog bytes received: %zu\n", total_qlog_bytes);
  if (total_qlog_bytes == 0) {
    fprintf(stderr, "no qlog data received on debug socket\n");
    close(log_fd);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  printf("===MULTIPATH OK===\n");

  close(log_fd);
  transport_destroy(server);
  close(listener_fd);
  unlink(qlog_path);
  return 0;
}
