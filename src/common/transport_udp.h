#ifndef QLINQ_TRANSPORT_UDP_H
#define QLINQ_TRANSPORT_UDP_H

#include <stddef.h>
#include <sys/socket.h>
#include <sys/uio.h>

/* Returns 0 when every datagram was sent, 1 for a non-fatal would-block or
 * partial send, and -1 for a hard socket error. */
int transport_udp_send_batch(int fd, const struct sockaddr *destination,
                             socklen_t destination_len,
                             const struct iovec *datagrams, size_t count);

#endif
