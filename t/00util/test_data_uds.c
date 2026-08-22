#include "data_uds.h"
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

typedef struct {
  int calls;
  uint8_t payload[64];
  size_t size;
  uint8_t priority;
} test_state_t;

static void on_packet(void *user_data, const moq_track_id_t *track_id,
                      const uint8_t *buf, size_t size, uint8_t priority) {
  test_state_t *state = user_data;
  if (track_id->type != MOQ_TRACK_DATA ||
      strcmp(track_id->name, "partial") != 0 || size > sizeof(state->payload))
    return;
  memcpy(state->payload, buf, size);
  state->size = size;
  state->priority = priority;
  state->calls++;
}

static int write_bytewise(int fd, data_uds_t *uds, const uint8_t *buf,
                          size_t size) {
  for (size_t i = 0; i < size; i++) {
    if (write(fd, buf + i, 1) != 1)
      return -1;
    data_uds_tick(uds);
  }
  return 0;
}

static int read_exact(int fd, void *buf, size_t size) {
  size_t done = 0;
  while (done < size) {
    ssize_t ret = read(fd, (uint8_t *)buf + done, size - done);
    if (ret < 0 && errno == EINTR)
      continue;
    if (ret <= 0)
      return -1;
    done += (size_t)ret;
  }
  return 0;
}

int main(void) {
  if (data_uds_create("../invalid", on_packet, NULL, NULL) != NULL) {
    fprintf(stderr, "unsafe socket name was accepted\n");
    return 1;
  }

  test_state_t state = {0};
  data_uds_t *uds =
      data_uds_create("qlinq-data-uds-test", on_packet, NULL, &state);
  if (!uds)
    return 1;

  const char *socket_path = "/tmp/qlinq-data-uds-test.sock";
  struct stat st;
  if (stat(socket_path, &st) != 0 || (st.st_mode & 0777) != 0600) {
    fprintf(stderr, "UDS permissions are not private\n");
    data_uds_destroy(uds);
    return 1;
  }

  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un addr = {.sun_family = AF_UNIX};
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
  if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    data_uds_destroy(uds);
    return 1;
  }
  data_uds_tick(uds);

  const char *name = "partial";
  uint8_t registration[3 + 7] = {MOQ_TRACK_DATA, MOQ_TRACK_FLAG_FEC_ENABLED, 7};
  memcpy(registration + 3, name, 7);
  if (write_bytewise(fd, uds, registration, sizeof(registration)) != 0) {
    close(fd);
    data_uds_destroy(uds);
    return 1;
  }

  const uint8_t payload[] = "framed-payload";
  uint32_t payload_size = sizeof(payload);
  uint8_t frame[5 + sizeof(payload)];
  memcpy(frame, &payload_size, 4);
  frame[4] = 2;
  memcpy(frame + 5, payload, sizeof(payload));
  if (write_bytewise(fd, uds, frame, sizeof(frame)) != 0 || state.calls != 1 ||
      state.size != sizeof(payload) || state.priority != 2 ||
      memcmp(state.payload, payload, sizeof(payload)) != 0) {
    fprintf(stderr, "partial input framing failed\n");
    close(fd);
    data_uds_destroy(uds);
    return 1;
  }

  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                          .name = "partial"};
  const uint8_t reply[] = "queued-reply";
  if (!data_uds_send(uds, &track, reply, sizeof(reply), 1)) {
    close(fd);
    data_uds_destroy(uds);
    return 1;
  }
  uint32_t reply_size;
  uint8_t reply_priority;
  uint8_t reply_buf[sizeof(reply)];
  if (read_exact(fd, &reply_size, sizeof(reply_size)) != 0 ||
      read_exact(fd, &reply_priority, sizeof(reply_priority)) != 0 ||
      reply_size != sizeof(reply) || reply_priority != 1 ||
      read_exact(fd, reply_buf, sizeof(reply_buf)) != 0 ||
      memcmp(reply_buf, reply, sizeof(reply)) != 0) {
    fprintf(stderr, "queued output framing failed\n");
    close(fd);
    data_uds_destroy(uds);
    return 1;
  }

  close(fd);
  data_uds_destroy(uds);
  printf("===DATA UDS OK===\n");
  return 0;
}
