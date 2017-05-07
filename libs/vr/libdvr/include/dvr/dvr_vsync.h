#ifndef ANDROID_DVR_VSYNC_H_
#define ANDROID_DVR_VSYNC_H_

#include <stdint.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

typedef struct DvrVSyncClient DvrVSyncClient;

// Creates a new client to the system vsync service.
int dvrVSyncClientCreate(DvrVSyncClient** client_out);

// Destroys the vsync client.
void dvrVSyncClientDestroy(DvrVSyncClient* client);

// Get the estimated timestamp of the next GPU lens warp preemption event in/
// ns. Also returns the corresponding vsync count that the next lens warp
// operation will target.
int dvrVSyncClientGetSchedInfo(DvrVSyncClient* client, int64_t* vsync_period_ns,
                               int64_t* next_timestamp_ns,
                               uint32_t* next_vsync_count);

__END_DECLS

#endif  // ANDROID_DVR_VSYNC_H_
