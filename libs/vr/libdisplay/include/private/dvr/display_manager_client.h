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

DvrDisplayManagerClient* dvrDisplayManagerClientCreate();

void dvrDisplayManagerClientDestroy(DvrDisplayManagerClient* client);

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

// Populates |surface_buffers| with the list of buffers for |surface_id|.
// |surface_id| should be a valid ID from the list of surfaces.
//
// @return Returns 0 on success. Otherwise it returns a negative error value.
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
