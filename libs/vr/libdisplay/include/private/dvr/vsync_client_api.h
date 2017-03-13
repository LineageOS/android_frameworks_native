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
typedef struct dvr_vsync_client dvr_vsync_client;

// Creates a new client to the system vsync service.
dvr_vsync_client* dvr_vsync_client_create();

// Destroys the vsync client.
void dvr_vsync_client_destroy(dvr_vsync_client* client);

// Get the estimated timestamp of the next GPU lens warp preemption event in
// ns. Also returns the corresponding vsync count that the next lens warp
// operation will target. This call has the same side effect on events as
// Acknowledge, which saves an IPC message.
int dvr_vsync_client_get_sched_info(dvr_vsync_client* client,
                                    int64_t* vsync_period_ns,
                                    int64_t* next_timestamp_ns,
                                    uint32_t* next_vsync_count);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ANDROID_DVR_VSYNC_CLIENT_API_H_
