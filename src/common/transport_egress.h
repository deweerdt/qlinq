#ifndef QLINQ_TRANSPORT_EGRESS_H
#define QLINQ_TRANSPORT_EGRESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>

typedef struct {
  struct sockaddr_storage destination;
  socklen_t destination_len;
  uint8_t *data;
  size_t size;
} transport_egress_packet_t;

typedef struct {
  transport_egress_packet_t *packets;
  size_t capacity;
  size_t max_bytes;
  size_t head;
  size_t count;
  size_t bytes;
  size_t peak_count;
  size_t peak_bytes;
  uint64_t packets_sent;
  uint64_t bytes_sent;
  uint64_t would_block;
  uint64_t send_errors;
  uint64_t packets_queued;
  uint64_t bytes_queued;
  uint64_t packets_dropped;
} transport_egress_t;

bool transport_egress_init(transport_egress_t *egress, size_t max_packets,
                           size_t max_bytes);
void transport_egress_destroy(transport_egress_t *egress);
bool transport_egress_can_accept(const transport_egress_t *egress,
                                 size_t packets, size_t bytes);
bool transport_egress_submit(transport_egress_t *egress, int fd,
                             const struct sockaddr *destination,
                             socklen_t destination_len,
                             const struct iovec *datagrams, size_t count);
bool transport_egress_flush(transport_egress_t *egress, int fd);

#endif
