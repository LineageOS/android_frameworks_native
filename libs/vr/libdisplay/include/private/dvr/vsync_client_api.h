#ifndef ANDROID_DVR_VSYNC_CLIENT_API_H_
#define ANDROID_DVR_VSYNC_CLIENT_API_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// A client of the vsync service.
//
// The "dvr_vsync_client" structure wraps a client connection to the
// system vsync service. It is used to synchronize application drawing
// with the scanout of the display.
typedef struct dvr_vsync_client dreamos_vsync_client;

// Creates a new client to the system vsync service.
dvr_vsync_client* dvr_vsync_client_create();

// Destroys the vsync client.
void dvr_vsync_client_destroy(dvr_vsync_client* client);

// Blocks until the next vsync signal.
// The timestamp (in ns) is written into |*timestamp_ns| when it is non-NULL.
// Returns 0 upon success, or -errno.
int dvr_vsync_client_wait(dvr_vsync_client* client, int64_t* timestamp_ns);

// Returns the file descriptor used to communicate with the vsync service.
int dvr_vsync_client_get_fd(dvr_vsync_client* client);

// Clears the select/poll/epoll event so that subsequent calls to these
// will not signal until the next vsync.
int dvr_vsync_client_acknowledge(dvr_vsync_client* client);

// Gets the timestamp of the last vsync signal in ns. This call has the
// same side effects on events as acknowledge.
int dvr_vsync_client_get_last_timestamp(dvr_vsync_client* client,
                                        int64_t* timestamp_ns);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ANDROID_DVR_VSYNC_CLIENT_API_H_
