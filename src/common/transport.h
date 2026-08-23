/* transport.h
 *
 * design philosophy:
 * this interface uses media over quic (MoQ) and flexicast concepts as
 * architectural design blueprints rather than fully compliant protocols.
 * by adopting pub/sub decoupling, stateless loss recovery, and single-publish
 * track fan-out, we keep the codebase clean, lightweight, and simple while
 * retaining low-latency multi-client capabilities.
 */

#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* opaque handles for transport state and connections */
typedef struct transport_t transport_t;
typedef struct transport_conn_t transport_conn_t;

typedef enum {
  MOQ_TRACK_VIDEO = 0,
  MOQ_TRACK_AUDIO = 1,
  MOQ_TRACK_INPUT = 2,
  MOQ_TRACK_TEXT = 3, /* subtitles, chat, or performance statistics */
  MOQ_TRACK_DATA = 4, /* generic raw data tunnel (e.g. TUN network packets) */
  MOQ_TRACK_TELEMETRY = 6, /* one-way delay / network telemetry */
} moq_track_type_t;

#define MOQ_TRACK_FLAG_RELIABLE (1 << 0)
#define MOQ_TRACK_FLAG_FEC_ENABLED (1 << 1)
#define MOQ_TRACK_FLAG_FEC_RATELESS (1 << 2)

typedef struct {
  moq_track_type_t type;
  uint8_t flags;
  char name[64];
} moq_track_id_t;

/* represents an object (e.g. video frame or audio chunk) */
typedef struct {
  moq_track_id_t track_id;
  uint64_t group_id;  /* gop index or time group */
  uint64_t object_id; /* frame/packet sequence number */
  const uint8_t *data;
  size_t size;
  bool is_keyframe; /* true if object starts a new group */
  uint8_t priority; /* 0 = low, 1 = medium, 2 = high */
} moq_object_t;

typedef enum {
  TRANSPORT_EVENT_CONNECTED,
  TRANSPORT_EVENT_DISCONNECTED,
  TRANSPORT_EVENT_SUBSCRIBE,     /* client subscribed to a track */
  TRANSPORT_EVENT_UNSUBSCRIBE,   /* client unsubscribed from a track */
  TRANSPORT_EVENT_OBJECT,        /* received a track object */
  TRANSPORT_EVENT_AUTH,          /* server received authentication token */
  TRANSPORT_EVENT_AUTH_COMPLETE, /* client received authentication response */
  TRANSPORT_EVENT_KEYFRAME_REQUEST, /* client requested a video keyframe */
  TRANSPORT_EVENT_OBJECT_LOST       /* packet group failed FEC recovery and was
                                       evicted */
} transport_event_type_t;

typedef struct {
  transport_event_type_t type;
  transport_conn_t *conn;
  moq_track_id_t track_id; /* valid for subscribe / unsubscribe / object */
  moq_object_t object;     /* valid for object events */
  struct {
    const uint8_t *token;
    size_t token_len;
    bool success;
  } auth; /* valid for auth events */
} transport_event_t;

/* Pointers inside an event, including object.data and auth.token, are borrowed
 * and remain valid only for the duration of the callback. */

/* callback for receiving transport events */
typedef void (*transport_callback_t)(void *user_data,
                                     const transport_event_t *event);

#define TRANSPORT_MAX_PATHS 4

/* Wire and flow-control limits enforced by the transport. */
#define TRANSPORT_MAX_RELIABLE_OBJECT_SIZE ((1024U * 1024U) - 16U)
#define TRANSPORT_MAX_FEC_RECORD_SIZE UINT16_MAX

#define TRANSPORT_APP_ERROR_PROTOCOL 0x100U
#define TRANSPORT_APP_ERROR_AUTHENTICATION 0x101U
#define TRANSPORT_APP_ERROR_RESOURCE_LIMIT 0x102U

typedef struct {
  const char *bind_hosts[TRANSPORT_MAX_PATHS];
  size_t num_bind_hosts;
  const char *remote_hosts[TRANSPORT_MAX_PATHS];
  size_t num_remote_hosts;
  uint16_t port;
  const char *cert_file; /* required for server */
  const char *key_file;  /* required for server */
  const char *ca_file;   /* CA bundle path for validating peer certificates */
  bool verify_peer;      /* require and verify peer certificate (mTLS) */
  bool allow_insecure_peer; /* explicit opt-in for tests; never use in
                               production */
  transport_callback_t callback;
  void *user_data;
  uint8_t simulated_loss_rate; /* 0 to 100 representing percentage of packets to
                                  drop */
} transport_config_t;

/* create and destroy transport instances */
transport_t *transport_create(const transport_config_t *config);
void transport_destroy(transport_t *t);

/* drive the event loop and process timers */
void transport_tick(transport_t *t);

typedef enum {
  TRANSPORT_PUBLISH_DELIVERED,
  TRANSPORT_PUBLISH_BUFFERED,
  TRANSPORT_PUBLISH_NO_RECIPIENTS,
  TRANSPORT_PUBLISH_PARTIAL,
  TRANSPORT_PUBLISH_BACKPRESSURE,
  TRANSPORT_PUBLISH_INVALID,
  TRANSPORT_PUBLISH_ERROR
} transport_publish_result_t;

/* Detailed publication result. PARTIAL means at least one eligible peer was
 * queued successfully and at least one failed. */
transport_publish_result_t transport_publish_ex(transport_t *t,
                                                const moq_object_t *obj);

/* Compatibility wrapper: true only when the object was delivered, buffered,
 * or had no eligible recipients. */
bool transport_publish(transport_t *t, const moq_object_t *obj);

/* subscribe to a media track (client-side) */
bool transport_subscribe(transport_t *t, moq_track_id_t track_id);

/* request a video keyframe from the publisher (client-side) */
bool transport_request_keyframe(transport_t *t, moq_track_id_t track_id);

/* send private unicast data (such as input events) to a specific connection */
bool transport_send_unicast(transport_t *t, transport_conn_t *conn,
                            const void *data, size_t size);

/* initiate session authentication (client-side) */
bool transport_send_auth(transport_t *t, transport_conn_t *conn,
                         const uint8_t *token, size_t token_len);

/* respond to connection authentication challenge (server-side) */
bool transport_respond_auth(transport_t *t, transport_conn_t *conn,
                            bool success);

/* connect to a unix domain socket and stream quicly debug events (qlog) */
int transport_enable_qlog(const char *socket_path);

/* close an active connection */
void transport_close_conn(transport_t *t, transport_conn_t *conn);

/* query latest estimated bandwidth in bytes per second */
uint64_t transport_get_estimated_bandwidth(transport_t *t);

typedef struct {
  uint64_t sent;
  uint64_t lost;
  uint32_t rtt;
  double relative_owd;
  double ewma_latency;
} transport_path_stats_t;

bool transport_get_path_stats(transport_t *t, size_t path_idx,
                              transport_path_stats_t *stats);

/* mock a local IP interface addition for testing multipath */
void transport_mock_iface_add(transport_t *t, const char *ip_addr);

/* Deterministic path controls for integration tests. The override remains in
 * effect for the lifetime of the current connections. */
bool transport_mock_path_state(transport_t *t, size_t path_idx,
                               uint32_t packets_per_second, double latency_ms,
                               double loss_rate);

size_t transport_get_datagram_symbol_size(const transport_t *t);

/* check if a track is ready for more data (application-layer backpressure) */
bool transport_is_track_ready(transport_t *t, const moq_track_id_t *track_id);

/* get current time in milliseconds */
int64_t transport_get_time_ms(void);

/* query earliest timeout timestamp in milliseconds for pacer and timers */
int64_t transport_get_first_timeout(transport_t *t);

struct pollfd;

/* collect socket file descriptors for polling */
size_t transport_get_poll_fds(transport_t *t, struct pollfd *fds,
                              size_t max_fds);

#endif /* TRANSPORT_H */
