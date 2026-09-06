/* Operational lifecycle integration test. */

#include "transport.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define TEST_PORT 10001
#define STEP_US 5000

typedef struct {
  transport_t *transport;
  bool is_server;
  uint32_t connected_count;
  uint32_t authenticated_count;
  uint32_t disconnected_count;
  uint32_t last_connection_id;
  bool last_disconnect_remote;
  uint64_t last_disconnect_error;
  char last_disconnect_reason[128];
  uint64_t log_count;
} lifecycle_state_t;

static void on_log(void *user_data, const transport_log_event_t *event) {
  lifecycle_state_t *state = user_data;
  if (event && event->component && event->message)
    state->log_count++;
}

static void on_event(void *user_data, const transport_event_t *event) {
  lifecycle_state_t *state = user_data;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    state->connected_count++;
    state->last_connection_id =
        transport_get_conn_id(state->transport, event->conn);
    if (!state->is_server)
      (void)transport_send_auth(state->transport, event->conn,
                                (const uint8_t *)"operational-test", 16);
    break;
  case TRANSPORT_EVENT_AUTH:
    if (state->is_server) {
      (void)transport_respond_auth(state->transport, event->conn, true);
      state->authenticated_count++;
    }
    break;
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    if (event->auth.success)
      state->authenticated_count++;
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    state->disconnected_count++;
    state->last_disconnect_remote = event->disconnect.remote;
    state->last_disconnect_error = event->disconnect.error_code;
    snprintf(state->last_disconnect_reason,
             sizeof(state->last_disconnect_reason), "%s",
             event->disconnect.reason ? event->disconnect.reason : "");
    break;
  default:
    break;
  }
}

static transport_t *create_server(lifecycle_state_t *state) {
  transport_config_t config = {0};
  config.bind_hosts[0] = "127.0.0.1";
  config.num_bind_hosts = 1;
  config.port = TEST_PORT;
  config.cert_file = "t/assets/server.crt";
  config.key_file = "t/assets/server.key";
  config.allow_insecure_peer = true;
  config.callback = on_event;
  config.user_data = state;
  config.log_callback = on_log;
  config.log_user_data = state;
  state->is_server = true;
  state->transport = transport_create(&config);
  return state->transport;
}

static transport_t *create_client(lifecycle_state_t *state) {
  transport_config_t config = {0};
  config.bind_hosts[0] = "127.0.0.1";
  config.num_bind_hosts = 1;
  config.remote_hosts[0] = "127.0.0.1";
  config.num_remote_hosts = 1;
  config.port = TEST_PORT;
  config.allow_insecure_peer = true;
  config.reconnect_enabled = true;
  config.reconnect_initial_delay_ms = 25;
  config.reconnect_max_delay_ms = 100;
  config.callback = on_event;
  config.user_data = state;
  config.log_callback = on_log;
  config.log_user_data = state;
  state->is_server = false;
  state->transport = transport_create(&config);
  return state->transport;
}

static bool drive_until_authenticated(transport_t *server,
                                      lifecycle_state_t *server_state,
                                      transport_t *client,
                                      lifecycle_state_t *client_state,
                                      uint32_t server_target,
                                      uint32_t client_target, int iterations) {
  while (iterations-- > 0) {
    transport_tick(server);
    transport_tick(client);
    if (server_state->authenticated_count >= server_target &&
        client_state->authenticated_count >= client_target)
      return true;
    usleep(STEP_US);
  }
  return false;
}

int main(void) {
  lifecycle_state_t server_state = {0};
  lifecycle_state_t replacement_state = {0};
  lifecycle_state_t client_state = {0};

  transport_t *server = create_server(&server_state);
  if (server && (transport_reload_credentials(server, "t/assets/server.crt",
                                              "t/assets/does-not-exist.key") ||
                 transport_reload_credentials(server, "t/assets/verified.crt",
                                              "t/assets/unsafe.key") ||
                 !transport_reload_credentials(server, "t/assets/server.crt",
                                               "t/assets/server.key"))) {
    fprintf(stderr,
            "credential reload atomicity or private-key policy failed\n");
    transport_destroy(server);
    return 1;
  }
  transport_t *client = create_client(&client_state);
  if (!server || !client) {
    fprintf(stderr, "unable to create operational-test transports\n");
    if (client)
      transport_destroy(client);
    if (server)
      transport_destroy(server);
    return 1;
  }

  if (!drive_until_authenticated(server, &server_state, client, &client_state,
                                 1, 1, 400)) {
    fprintf(stderr, "initial connection did not authenticate\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }
  uint32_t initial_connection_id = client_state.last_connection_id;
  transport_path_stats_t path = {0};
  if (initial_connection_id == 0 ||
      !transport_get_path_stats(client, 0, &path) ||
      path.lifecycle != TRANSPORT_PATH_ACTIVE) {
    fprintf(stderr, "initial connection path never became active\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }

  transport_shutdown(server, "planned peer restart");
  int iterations = 600;
  while (iterations-- > 0 && (server_state.disconnected_count == 0 ||
                              client_state.disconnected_count == 0)) {
    transport_tick(server);
    transport_tick(client);
    usleep(STEP_US);
  }
  if (server_state.disconnected_count != 1 ||
      client_state.disconnected_count != 1 ||
      server_state.last_disconnect_remote ||
      !client_state.last_disconnect_remote ||
      server_state.last_disconnect_error != 0 ||
      client_state.last_disconnect_error != 0 ||
      strcmp(server_state.last_disconnect_reason, "planned peer restart") !=
          0 ||
      strcmp(client_state.last_disconnect_reason, "planned peer restart") !=
          0) {
    fprintf(stderr, "planned restart close diagnostics were incorrect\n");
    transport_destroy(client);
    transport_destroy(server);
    return 1;
  }
  transport_destroy(server);
  server = NULL;

  /* Let the client create the replacement connection while the peer is down,
   * then recreate the listener. This covers retransmission across restart. */
  for (int i = 0; i < 20; i++) {
    transport_tick(client);
    usleep(STEP_US);
  }
  transport_t *replacement = create_server(&replacement_state);
  if (!replacement ||
      !drive_until_authenticated(replacement, &replacement_state, client,
                                 &client_state, 1, 2, 800)) {
    transport_stats_t client_diagnostic = {0};
    transport_stats_t server_diagnostic = {0};
    (void)transport_get_stats(client, &client_diagnostic);
    if (replacement)
      (void)transport_get_stats(replacement, &server_diagnostic);
    fprintf(
        stderr,
        "client did not reconnect after peer restart (client_connected=%" PRIu32
        " client_auth=%" PRIu32 " server_connected=%" PRIu32
        " server_auth=%" PRIu32 " attempts=%" PRIu64 " success=%" PRIu64
        " failed=%" PRIu64 " client_active=%zu server_active=%zu)\n",
        client_state.connected_count, client_state.authenticated_count,
        replacement_state.connected_count,
        replacement_state.authenticated_count,
        client_diagnostic.reconnect_attempts,
        client_diagnostic.reconnect_succeeded,
        client_diagnostic.reconnect_failed,
        client_diagnostic.active_connections,
        server_diagnostic.active_connections);
    if (replacement)
      transport_destroy(replacement);
    transport_destroy(client);
    return 1;
  }

  transport_stats_t stats = {0};
  if (!transport_get_stats(client, &stats) || stats.reconnect_attempts == 0 ||
      stats.reconnect_succeeded != 1 || stats.reconnect_failed != 0 ||
      client_state.last_connection_id == 0 ||
      client_state.last_connection_id == initial_connection_id) {
    fprintf(stderr,
            "reconnect observability failed (attempts=%" PRIu64
            " succeeded=%" PRIu64 " failed=%" PRIu64 " old=%" PRIu32
            " new=%" PRIu32 ")\n",
            stats.reconnect_attempts, stats.reconnect_succeeded,
            stats.reconnect_failed, initial_connection_id,
            client_state.last_connection_id);
    transport_destroy(replacement);
    transport_destroy(client);
    return 1;
  }

  transport_shutdown(client, "test complete");
  iterations = 600;
  while (iterations-- > 0 && (!transport_is_drained(client) ||
                              !transport_is_drained(replacement))) {
    transport_tick(client);
    transport_tick(replacement);
    usleep(STEP_US);
  }
  if (!transport_is_drained(client) || !transport_is_drained(replacement)) {
    fprintf(stderr, "replacement connection did not drain\n");
    transport_destroy(replacement);
    transport_destroy(client);
    return 1;
  }

  transport_destroy(replacement);
  transport_destroy(client);
  printf("===OPERATIONAL OK===\n");
  return 0;
}
