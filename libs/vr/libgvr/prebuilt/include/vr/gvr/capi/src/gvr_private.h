#ifndef VR_GVR_CAPI_SRC_GVR_PRIVATE_H_
#define VR_GVR_CAPI_SRC_GVR_PRIVATE_H_

#include <stddef.h>

#include "vr/gvr/capi/include/gvr_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle to gvr_tracker_state object containing serialized state.
typedef struct gvr_tracker_state_ gvr_tracker_state;

// Opaque handle to gvr_display_synchronizer object for display synchronization.
typedef struct gvr_display_synchronizer_ gvr_display_synchronizer;

// Internal Google VR C API methods. These methods are exposed only to internal
// targets, but should follow all the same backwards-compatible restrictions
// as the public C API.

/// Sets whether asynchronous reprojection is currently enabled.
///
/// If enabled, frames will be collected by the rendering system and
/// asynchronously re-projected in sync with the scanout of the display. This
/// feature may not be available on every platform, and requires a
/// high-priority render thread with special extensions to function properly.
///
/// Note: On Android, this feature can be enabled solely via the GvrLayout Java
/// instance which (indirectly) owns this gvr_context. The corresponding
/// method call is GvrLayout.setAsyncReprojectionEnabled().
///
/// @param gvr Pointer to the gvr instance.
/// @Param enabled Whether to enable async reprojection.
/// @return Whether the setting was succesfully applied.
bool gvr_set_async_reprojection_enabled(gvr_context* gvr, bool enabled);

// Initializes necessary GL-related objects and uses the current thread and
// GL context for racing the scanline. This function should only be called
// by the SDK itself, not by any application, unless that application is
// providing a high-priority thread and GL context for async reprojection.
//
// Note: This method is private as it is intended for use solely by the
// hidden async reprojection implementation in ScanlineRacingRenderer.java,
// called in onSurfaceCreated().
//
// @param gvr Pointer to the gvr_context instance.
void gvr_on_surface_created_reprojection_thread(gvr_context* gvr);

// Renders the scanline layer. This function should only be called
// in the same thread that gvr_initialize_gl_projection_thread was called in.
// This function should only be called by the SDK itself, not by any
// application, unless that application is providing a high-priority
// thread and GL context for async reprojection.
//
// Note: This method is private as it is intended for use solely by the
// hidden async reprojection implementation in ScanlineRacingRenderer.java.
//
// @param gvr Pointer to the gvr_context instance.
void gvr_render_reprojection_thread(gvr_context* gvr);

// Signals to the reprojection thread that it is paused. This is necessary
// in case the application render thread is blocked on pending work by the
// reprojection thread. This function will abort any blocking.
//
// @param gvr Pointer to the gvr_context instance.
void gvr_on_pause_reprojection_thread(gvr_context* gvr);

// Sets the parameters for the external surface managed by the reprojection
// thread.
//
// @param gvr Pointer to the gvr_context instance.
// @param surface_id The ID of the external Surface managed by the reprojection
//     thread. The ID is issued by the SurfaceTextureManager.
// @param texture_id The GL texture ID associated with the external Surface.
// @param timestamp The timestamp of the most recent frame the Surface holds.
// @param surface_transfrom Matrix that transforms homogeneous texture coords to
//     the external surface texture space.
void gvr_update_surface_reprojection_thread(gvr_context* gvr,
      int32_t surface_id, int32_t texture_id, gvr_clock_time_point timestamp,
      gvr_mat4f surface_transform);

// Removes all external surfaces managed by the reprojection thread. This does
// not destoy the surfaces: it removes tracking by the reprojection thread.
//
// @param gvr Pointer to the gvr_context instance.
void gvr_remove_all_surfaces_reprojection_thread(gvr_context* gvr);

// Reconnects the sensors when the sensor producers are created internally.
//
// Note: This function is not thread-safe, and should be called only on the
// rendering thread. It is intended to be used internally by GvrLayout when
// the target presentation display changes.
//
// @param gvr Pointer to the gvr_context instance.
void gvr_reconnect_sensors(gvr_context* gvr);

// Sets VR viewer params for the current context.
//
// Note: This function does not update the viewer proto in the common storage
// location. Rather, it overrides the viewer params solely for the provided
// gvr_context.
//
// @param gvr Pointer to the gvr_context instance.
// @param serialized_viewer_params A pointer to the payload containing the
//     serialized viewer params proto.
// @param serialized_viewer_params_size_bytes The length in bytes of the
//     serialized viewer params payload.
// @return Whether the serialized viewer params proto was successfully applied.
bool gvr_set_viewer_params(gvr_context* gvr,
                           const void* serialized_viewer_params,
                           size_t serialized_viewer_params_size_bytes);

// Sets the lens offset.
//
// @param offset The offset of the lens center from the expected location in
// screen space.
void gvr_set_lens_offset(gvr_context* gvr, gvr_vec2f offset);

// Sets display metrics for the current context.
//
// Note: This function does not update the phone proto in the commom storage
// location. Rather, it overrides the internal metrics solely for the provided
// |gvr| context.
//
// @param gvr Pointer to the gvr_context instance.
// @param size_pixels The dimensions in pixels of the active display.
// @param meters_per_pixel The density of the current display in meters/pixel.
// @param border_size_meters The size of the border around the display
//     in meters.  When the device sits on a surface in the proper
//     orientation this is the distance from the surface to the edge
//     of the display.
void gvr_set_display_metrics(gvr_context* gvr, gvr_sizei size_pixels,
                             gvr_vec2f meters_per_pixel,
                             float border_size_meters);

// Sets the display rotation offset that is applied at distortion correction
// time to take into account the device's display orientation.
//
// For instance, calling this with display_output_rotation set to 1 allows
// clients to lock their phone orientation to portrait on an Android phone and
// still get a correctly rendered VR mode with the two eyes stacked up along the
// longer phone dimension.
//
// @param gvr Pointer to the gvr_context instance.
// @param display_output_rotation Value encoding the rotation used when
//     performing distortion correction. Supported values are:
//     0 - Default mode. Eye viewports are positioned side-by-side along the
//         "width" dimension, with left eye in the x < 0.5 half.
//     1 - Applies a clock-wise rotation of 90 degrees on the display when
//         doing distortion correction. Eye viewports are positioned
//         side-by-side along the "height" dimension, with left eye in the
//         y > 0.5 half.
// Rotation modes used when performing distortion correction.
enum {
  GVR_PRIVATE_DISPLAY_OUTPUT_ROTATION_0 = 0,
  GVR_PRIVATE_DISPLAY_OUTPUT_ROTATION_90 = 1,
};
void gvr_set_display_output_rotation(gvr_context* gvr,
                                     int32_t display_output_rotation);

// Gets the size of the border around the display used by the given gvr_context.
//
// @param gvr Pointer to the gvr_context instance.
float gvr_get_border_size_meters(const gvr_context* gvr);

// Returns whether the surface size was changed since the last call to this
// function (it's changed with gvr_set_surface_size()).
//
// @param gvr Pointer to the gvr_context instance.
// @return Whether the surface size was changed.
bool gvr_check_surface_size_changed(gvr_context* gvr);

// Returns the current surface size in pixels, or (0, 0) if the surface size
// matches that of the active display (which is the default).
//
// @param gvr Pointer to the gvr_context instance.
// @return The current surface size in pixels.
gvr_sizei gvr_get_surface_size(const gvr_context* gvr);

// Sets a handler that is called back when the back gesture is detected,
// which is when the phone changes from landscape to portrait orientation
// within a few seconds.
//
// @param gvr Pointer to the gvr_context instance.
// @param handler The event_handler callback. May be null to clear the
//     registered event_handler.
// @param user_data An opaque pointer to user_data which will be supplied
//     as the callback argument. The caller is responsible for ensuring the
//     validity of this data for the duration of the handler registration.
typedef void (*event_handler)(void* user_data);
void gvr_set_back_gesture_event_handler(gvr_context* gvr, event_handler handler,
                                        void* user_data);

// Internal method to pause head tracking used by GvrLayout. Disables all
// sensors (to save power) and gets the serialized tracker state.
//
// @param gvr Pointer to the gvr instance for which tracking will be paused and
//     sensors disabled.
//
// @return Pointer to a tracker_state object containing the serialized tracker
//     state. The caller is responsible for calling destroy on the returned
//     handle.
gvr_tracker_state* gvr_pause_tracking_get_state(gvr_context* gvr);

// Internal method to resume head tracking used by GvrLayout. Re-enables all
// sensors and sets the tracker state.
//
// @param gvr Pointer to the gvr instance for which tracking will be resumed.
//     serialized tracker state object.
// @param tracker_state Pointer to a tracker_state object containing the
//     serialized tracker state object.
void gvr_resume_tracking_set_state(
    gvr_context* gvr, gvr_tracker_state* tracker_state);

// Sets the internal flag that ignores calls to the public API's
// gvr_pause_tracking and gvr_resume_tracking.
// When true, the tracker is handled through GvrLayout
// gvr_pause_tracking_private / gvr_resume_tracking_private direct calls through
// the GvrApi instance are ignored. This is workaround to temporarily support
// clients using GvrLayout that manually call pause/ resume tracking.
// TODO(b/30404822) : clean this up once all existing clients move away from the
// obsolete behavior.
//
// @param gvr Pointer to the gvr instance.
// @param should_ignore Whether manual pause / resume tracker should be ignored.
void gvr_set_ignore_manual_tracker_pause_resume(gvr_context* gvr,
                                                bool should_ignore);

// Creates a new tracker state object from the serialized tracker state buffer.
//
// @param tracker_state_buffer Pointer to buffer containing the serialized
// tracker state.
// @param buf_size Size of the tracker state buffer.
//
// @return Pointer to a tracker_state object containing the serialized tracker
// state string. The caller is responsible for calling destroy on the returned
// handle.
gvr_tracker_state* gvr_tracker_state_create(const char* tracker_state_buffer,
                                            size_t buf_size);

// Gets the size of the buffer that is required to hold the serialized
// gvr_tracker_state.
//
// @param Pointer to a gvr_tracker_state object containing the serialized
// tracker state.
//
// @return Size of the buffer,
size_t gvr_tracker_state_get_buffer_size(gvr_tracker_state* tracker_state);

// Gets the buffer that holds the serialized gvr_tracker_state.
//
// @param Pointer to a tracker_state object containing the serialized tracker
// state.
//
// @return Pointer to the buffer.
const char* gvr_tracker_state_get_buffer(gvr_tracker_state* tracker_state);

// Destroys a gvr_tracker_state instance.
//
// @param tracker_state Pointer to a pointer of the gvr_tracker_state instance
// to be destroyed and nulled.
void gvr_tracker_state_destroy(gvr_tracker_state** tracker_state);

// Creates a new synchronizer instance.
//
// @return synchronizer Pointer to the new gvr_display_synchronizer instance.
gvr_display_synchronizer* gvr_display_synchronizer_create();

// Destroy the synchonronizer instance and null the pointer.
//
// @param synchronizer Pointer to a pointer to the gvr_display_synchronizer
//     instance.
void gvr_display_synchronizer_destroy(gvr_display_synchronizer** synchronizer);

// Resets the synchronizer with updated vsync timing data.
//
// @param synchronizer Pointer to the new gvr_display_synchronizer instance.
// @param expected_interval_nanos The expected average time between
//     synchronization times, in nanoseconds, or 0 if unknown.
// @param vsync_offset_nanos The duration, in nanos, such that the current sync
//     time minus the display vsync offset is the time when the physical
//     scan-out hardware begins to read data from the frame buffer.
void gvr_display_synchronizer_reset(gvr_display_synchronizer* synchronizer,
                                    int64_t expected_interval_nanos,
                                    int64_t vsync_offset_nanos);

// Updates the synchronizer with dispplay data for a new frame.
//
// @param vsync_time The new frame's vsync time.
// @param rotation_degrees The screen rotation from sensor space to display
//     space in degrees.
void gvr_display_synchronizer_update(gvr_display_synchronizer* synchronizer,
                                     gvr_clock_time_point vsync_time,
                                     int32_t rotation);

// Installs the display synchronizer into a GVR context.
//
// @param gvr Pointer to the current gvr_context instance.
// @param synchronizer Pointer to the gvr_display_synchronizer instance, to be
//     used by the context implementation during rendering.
void gvr_set_display_synchronizer(gvr_context* gvr,
                                  gvr_display_synchronizer* synchronizer);

// Sets the current error code. Overwrites any existing error code.
//
// @param gvr Pointer to the current gvr_context instance.
// @param error_code The error code to set.
void gvr_set_error(gvr_context* gvr, int32_t error_code);

// Called by the platform layer to to indicate the application is paused. (e.g.
// On Android, this function is called by GvrLayout.OnPause().)
//
// @param gvr Pointer to the current gvr_context instance.
void gvr_pause(gvr_context* gvr);

// Called by the platform layer to to indicate the application has resumed.
// (e.g. On Android, this function is called by GvrLayout.OnResume().)
//
// @param gvr Pointer to the current gvr_context instance.
void gvr_resume(gvr_context* gvr);

// Dumps additional data to logcat or disk to be included in bug reports.
//
// @param gvr Pointer to the current gvr_context instance.
void gvr_dump_debug_data(gvr_context* gvr);

// Returns true if the libgvr implementation is using the dedicated VR display
// service, false otherwise.
//
// @param gvr Pointer to the current gvr_context instance.
bool gvr_using_vr_display_service(gvr_context* gvr);

// Creates a new gvr_context using the supplied tracker, only for testing.
//
// Note: The pose returned is *in start space*. This is *not* the same space as
// the pose normally returned by |gvr_get_head_space_from_start_space_rotation|.
//
// @param tracker The test pose tracker to use.
// @param user_data An opaque pointer to user_data which will be supplied
//     as the callback argument. The caller is responsible for ensuring the
//     validity of this data for the duration of the handler registration.
typedef gvr_mat4f (*gvr_test_pose_tracker)(void*, gvr_clock_time_point);
gvr_context* gvr_create_with_tracker_for_testing(gvr_test_pose_tracker tracker,
                                                 void* user_data);

// Request resource sharing between the application's OpenGL context and the
// scanline racing context.  This must be called before gvr_initialize_gl.
// <p>
// This is a best effort request rather than an explicit toggle; it is a no-op
// if the client does not enable async reprojection, or if the platform does not
// support resource sharing.
// <p>
// The only OpenGL resource that we need sharing for is the framebuffer texture
// that the app renders to, and that distortion samples from.  If resource
// sharing is disabled, then we use an EGLImage so that it can be accessed from
// both contexts.
// <p>
// Also sets a callback function that is called at the end of gvr_initialize_gl,
// while the application's OpenGL context is still active on the current thread.
// This is used internally to notify the scanline racing renderer that the
// application's OpenGL context has been created.
//
// @param gvr Pointer to the current gvr_context instance.
// @param handler Callback that gets called when the app context becomes ready.
// @param user_data An opaque pointer to user data which will be supplied
//     as the callback argument. The caller is responsible for ensuring the
//     validity of this data for the duration of the handler registration.
typedef void (*gvr_egl_context_listener)(void*);
void gvr_request_context_sharing(gvr_context* gvr,
                                 gvr_egl_context_listener handler,
                                 void* user_data);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // VR_GVR_CAPI_SRC_GVR_PRIVATE_H_
