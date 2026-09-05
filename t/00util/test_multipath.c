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

typedef struct {
  bool connected;
  bool subscribed;
  bool object_received;
  uint8_t received_data[100];
  size_t received_size;
  transport_t *transport;
  transport_conn_t *conn;
} test_state_t;

static void on_server_event(void *user_data, const transport_event_t *event) {
  test_state_t *state = user_data;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    state->conn = event->conn;
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
    state->conn = event->conn;
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

static bool test_single_remote_fanout(void) {
  test_state_t server_state = {0};
  test_state_t client_state = {0};

  transport_config_t server_cfg = {0};
  server_cfg.bind_hosts[0] = "127.70.1.1";
  server_cfg.num_bind_hosts = 1;
  server_cfg.port = 9877;
  server_cfg.cert_file = "t/assets/server.crt";
  server_cfg.key_file = "t/assets/server.key";
  server_cfg.callback = on_server_event;
  server_cfg.allow_insecure_peer = true;
  server_cfg.user_data = &server_state;

  transport_config_t client_cfg = {0};
  client_cfg.bind_hosts[0] = "127.71.1.2";
  client_cfg.bind_hosts[1] = "127.72.2.23";
  client_cfg.bind_hosts[2] = "127.73.3.34";
  client_cfg.num_bind_hosts = 3;
  client_cfg.remote_hosts[0] = "127.70.1.1";
  client_cfg.num_remote_hosts = 1;
  client_cfg.port = 9877;
  client_cfg.callback = on_client_event;
  client_cfg.allow_insecure_peer = true;
  client_cfg.user_data = &client_state;

  transport_t *server = transport_create(&server_cfg);
  if (!server)
    return false;
  server_state.transport = server;
  transport_t *client = transport_create(&client_cfg);
  if (!client) {
    transport_destroy(server);
    return false;
  }
  client_state.transport = client;

  transport_conn_stats_t stats = {0};
  int retries = 300;
  while (retries-- > 0) {
    transport_tick(server);
    transport_tick(client);
    if (server_state.connected && client_state.connected && client_state.conn &&
        transport_get_conn_stats(client, client_state.conn, &stats) &&
        stats.quic_paths_validated >= 2)
      break;
    usleep(10 * 1000);
  }

  bool ok = server_state.connected && client_state.connected &&
            client_state.conn &&
            transport_get_conn_stats(client, client_state.conn, &stats) &&
            stats.quic_paths_created >= 2 && stats.quic_paths_validated >= 2 &&
            stats.quic_paths_validation_failed == 0;
  if (!ok)
    fprintf(stderr,
            "single-remote path validation failed: created=%lu "
            "validated=%lu failed=%lu\n",
            (unsigned long)stats.quic_paths_created,
            (unsigned long)stats.quic_paths_validated,
            (unsigned long)stats.quic_paths_validation_failed);

  transport_destroy(client);
  transport_destroy(server);
  return ok;
}

#include <signal.h>

int main(void) {
  signal(SIGPIPE, SIG_IGN);
  const char *qlog_path = "tmp/test_qlog.sock";
  mkdir("tmp", 0777);

  printf("testing multiple local interfaces with one remote endpoint...\n");
  if (!test_single_remote_fanout())
    return 1;

  int listener_fd = setup_qlog_listener(qlog_path);
  if (listener_fd < 0) {
    fprintf(stderr, "failed to setup qlog listener\n");
    return 1;
  }

  test_state_t server_state = {0};
  test_state_t client_state = {0};

  /* These loopback tuples deliberately do not share /24 prefixes. */
  transport_config_t server_cfg = {0};
  server_cfg.bind_hosts[0] = "127.0.1.1";
  server_cfg.bind_hosts[1] = "127.10.2.41";
  server_cfg.bind_hosts[2] = "127.20.3.77";
  server_cfg.bind_hosts[3] = "127.30.4.99";
  server_cfg.num_bind_hosts = 4;
  server_cfg.port = 9876;
  server_cfg.cert_file = "t/assets/server.crt";
  server_cfg.key_file = "t/assets/server.key";
  server_cfg.callback = on_server_event;
  server_cfg.allow_insecure_peer = true;
  server_cfg.user_data = &server_state;

  /* Start with two configured local paths; add the other two at runtime. */
  transport_config_t client_cfg = {0};
  client_cfg.bind_hosts[0] = "127.0.1.2";
  client_cfg.bind_hosts[1] = "127.40.9.12";
  client_cfg.num_bind_hosts = 2;
  client_cfg.remote_hosts[0] = "127.0.1.1";
  client_cfg.remote_hosts[1] = "127.10.2.41";
  client_cfg.remote_hosts[2] = "127.20.3.77";
  client_cfg.remote_hosts[3] = "127.30.4.99";
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

  /* The hot-added addresses also have unrelated prefixes and host octets. */
  printf("triggering secondary loopback path validation...\n");
  transport_mock_iface_add(client, "127.50.8.23");
  transport_mock_iface_add(client, "127.60.7.34");

  /* tick transports to process interface updates and complete validation */
  retries = 200;
  transport_conn_stats_t conn_stats = {0};
  while (retries-- > 0) {
    transport_tick(server);
    transport_tick(client);
    drain_qlog(log_fd);
    if (client_state.conn &&
        transport_get_conn_stats(client, client_state.conn, &conn_stats) &&
        conn_stats.quic_paths_validated >= 3)
      break;
    usleep(10 * 1000);
  }

  if (!client_state.conn ||
      !transport_get_conn_stats(client, client_state.conn, &conn_stats) ||
      conn_stats.quic_paths_created < 3 ||
      conn_stats.quic_paths_validated < 3 ||
      conn_stats.quic_paths_validation_failed != 0) {
    fprintf(stderr,
            "secondary path validation failed: created=%lu validated=%lu "
            "failed=%lu\n",
            (unsigned long)conn_stats.quic_paths_created,
            (unsigned long)conn_stats.quic_paths_validated,
            (unsigned long)conn_stats.quic_paths_validation_failed);
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
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

  /* Verify all four local sockets remain observable. */
  int socket_count = 0;
  for (size_t i = 0; i < 4; i++) {
    transport_path_stats_t stats;
    if (transport_get_path_stats(client, i, &stats))
      socket_count++;
  }

  if (socket_count < 4) {
    fprintf(stderr, "not all 4 path sockets are active: count=%d\n",
            socket_count);
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
  }

  /* Test 60/5/10/25 split for 1000 packets */
  printf("testing 60/5/10/25 split for 1000 packets...\n");
  if (!transport_mock_path_state(server, 0, 60, 10.0, 0.0) ||
      !transport_mock_path_state(server, 1, 5, 10.0, 0.0) ||
      !transport_mock_path_state(server, 2, 10, 10.0, 0.0) ||
      !transport_mock_path_state(server, 3, 25, 10.0, 0.0)) {
    fprintf(stderr, "failed to install deterministic path state\n");
    close(log_fd);
    transport_destroy(client);
    transport_destroy(server);
    close(listener_fd);
    unlink(qlog_path);
    return 1;
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
  size_t symbol_size = transport_get_datagram_symbol_size(server);

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
