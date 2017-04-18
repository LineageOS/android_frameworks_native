#ifndef DVR_DISPLAY_MANAGER_CLIENT_H_
#define DVR_DISPLAY_MANAGER_CLIENT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DvrDisplayManagerClient DvrDisplayManagerClient;
typedef struct DvrDisplayManagerClientSurfaceList
    DvrDisplayManagerClientSurfaceList;
typedef struct DvrDisplayManagerClientSurfaceBuffers
    DvrDisplayManagerClientSurfaceBuffers;
typedef struct DvrBuffer DvrBuffer;

DvrDisplayManagerClient* dvrDisplayManagerClientCreate();

void dvrDisplayManagerClientDestroy(DvrDisplayManagerClient* client);

DvrBuffer* dvrDisplayManagerSetupNamedBuffer(DvrDisplayManagerClient* client,
                                             const char* name, size_t size,
                                             uint64_t usage0, uint64_t usage1);

// Return an event fd for checking if there was an event on the server
// Note that the only event which will be flagged is POLLIN. You must use
// dvrDisplayManagerClientTranslateEpollEventMask in order to get the real
// event flags.
// @return the fd
int dvrDisplayManagerClientGetEventFd(DvrDisplayManagerClient* client);

// Once you have received an epoll event, you must translate it to its true
// flags. This is a workaround for working with UDS.
// @param in_events pass in the epoll revents that were initially returned
// @param on success, this value will be overwritten with the true epoll values
// @return 0 on success, non-zero otherwise
int dvrDisplayManagerClientTranslateEpollEventMask(
    DvrDisplayManagerClient* client, int in_events, int* out_events);

// If successful, populates |surface_list| with a list of application
// surfaces the display is currently using.
//
// @return 0 on success. Otherwise it returns a negative error value.
int dvrDisplayManagerClientGetSurfaceList(
    DvrDisplayManagerClient* client,
    DvrDisplayManagerClientSurfaceList** surface_list);

void dvrDisplayManagerClientSurfaceListDestroy(
    DvrDisplayManagerClientSurfaceList* surface_list);

// @return Returns the number of surfaces in the list.
size_t dvrDisplayManagerClientSurfaceListGetSize(
    DvrDisplayManagerClientSurfaceList* surface_list);

// @return Return a unique identifier for a client surface. The identifier can
// be used to query for other surface properties.
int dvrDisplayManagerClientSurfaceListGetSurfaceId(
    DvrDisplayManagerClientSurfaceList* surface_list, size_t index);

// @return Returns the stacking order of the client surface at |index|.
int dvrDisplayManagerClientSurfaceListGetClientZOrder(
    DvrDisplayManagerClientSurfaceList* surface_list, size_t index);

// @return Returns true if the client surface is visible, false otherwise.
bool dvrDisplayManagerClientSurfaceListGetClientIsVisible(
    DvrDisplayManagerClientSurfaceList* surface_list, size_t index);

// TODO(jwcai, hendrikw) Remove this after we replacing
// dvrDisplayManagerClientGetSurfaceBuffers is dvr_api.
int dvrDisplayManagerClientGetSurfaceBuffers(
    DvrDisplayManagerClient* client, int surface_id,
    DvrDisplayManagerClientSurfaceBuffers** surface_buffers);

void dvrDisplayManagerClientSurfaceBuffersDestroy(
    DvrDisplayManagerClientSurfaceBuffers* surface_buffers);

// @return Returns the number of buffers.
size_t dvrDisplayManagerClientSurfaceBuffersGetSize(
    DvrDisplayManagerClientSurfaceBuffers* surface_buffers);

// @return Returns the file descriptor for the buffer consumer at |index|.
int dvrDisplayManagerClientSurfaceBuffersGetFd(
    DvrDisplayManagerClientSurfaceBuffers* surface_buffers, size_t index);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // DVR_DISPLAY_MANAGER_CLIENT_H_
