#ifndef VR_GVR_CAPI_SRC_GVR_EXPERIMENTAL_H_
#define VR_GVR_CAPI_SRC_GVR_EXPERIMENTAL_H_

#include <stdbool.h>
#include <stdint.h>

#include "vr/gvr/capi/include/gvr_types.h"
#include "vr/gvr/capi/src/gvr_types_experimental.h"

#ifdef __cplusplus
extern "C" {
#endif

// NOTE: APIs added to this file are *not* part of the core GVR library, and
// should only be used for prototyping or experimental projects. The idea is
// that APIs added here can be used for testing and development, graduating to
// the core API (gvr.h or gvr_private.h) after we're ready to commit to them
// indefinitely.

// ************************************************************************** //
// *                     DaydreamOS experimental APIs                       * //
// ************************************************************************** //

/// Gets the position and rotation from start space to head space.  The head
/// space is a space where the head is at the origin and faces the -Z direction.
///
/// @param gvr Pointer to the gvr instance from which to get the pose.
/// @param time The time at which to get the head pose. The time should be in
///     the future. If the time is not in the future, it will be clamped to now.
/// @return A matrix representation of the position and rotation from start
//      space (the space where the head was last reset) to head space (the space
///     with the head at the origin, and the axes aligned to the view vector).
gvr_mat4f gvr_get_head_space_from_start_space_pose(
    gvr_context* gvr, const gvr_clock_time_point time);

/// Sets the compositor z-order of the swap chain.
///
/// @param swap_chain the swap chain to change.
/// @param z_order Z order, higher values are displayed on top of lower ones,
///     the default value is 0.
void gvr_swap_chain_set_z_order(const gvr_swap_chain* swap_chain, int z_order);

/// Creates a gvr_external_surface instance.
/// An external surface is mainly used to pass external content (such as video
/// frames, pre-rendered 2D Android UI) into distortion pass for compositing.
/// The method gvr_external_surface_get_surface can be used to bridge Android
/// components with GVR distortion pass via a traditional Android Surface
/// instance.
///
/// @param gvr Pointer to the gvr instance from which to create the external
///     surface.
/// @return Pointer to an allocated gvr_external_surface object. The caller
//      is responsible for calling gvr_external_surface_destroy() on the
///     returned object when it is no longer needed.
gvr_external_surface* gvr_external_surface_create(gvr_context* gvr);

/// Frees a gvr_external_surface instance and clears the pointer.
/// Note that once a gvr_external_surface is destroyed, the Java Surface object
/// returned from gvr_external_surface_get_surface remains to be accessible and
/// functioning. It's up to Java's garbage collection to release all resources
/// behind the Java Surface object.
///
/// @param surface Pointer to a pointer to the gvr_external_surface instance to
///     be destroyed and nulled.
void gvr_external_surface_destroy(gvr_external_surface** surface);

/// Get an Android Surface as a Java object from the gvr_external_surface. This
/// API is mainly used by standalone display service (aka when
/// gvr_using_vr_display_service returns true) to access an Android Surface.
///
/// @param surface The gvr_external_surface associated with the Android Surface.
///     Note that this API has to be called within a JNIEnv and is using the
///     JNIEnv passed in during gvr_create.
/// @return A jobject that is an instance of the 'android/view/Surface' Java
///     class, NULL on failure. Note that the return value is really an opaque
///     handle to a Java object and the life cycle of that object is maintained
///     by Java (i.e. it will get garbage collected eventually). Thus, there is
///     no need for an explicit destroy call.
void* gvr_external_surface_get_surface(const gvr_external_surface* surface);

/// Get the Surface ID associated with the gvr_external_surface. Note that the
/// returned ID is used for internal bookkeeping only and should not be used
/// by the app itself for lookups.
/// @param surface The gvr_external_surface to query the ID for.
/// @return The external surface ID associated with the gvr_external_surface.
int32_t gvr_external_surface_get_surface_id(
    const gvr_external_surface* surface);

/// Queries whether a particular GVR feature is supported by the underlying
/// platform.
///
/// @param gvr The context to query against.
/// @param feature The gvr_feature type being queried.
/// @return true if feature is supported, false otherwise.
bool gvr_experimental_is_feature_supported(const gvr_context* gvr,
                                           int32_t feature);

/// Sets the z order of the layer to be created.
/// Note that this API is a short-term workaround for SysUI work and is never
/// meant to graduate as is to either gvr.h or gvr_private.h. The proper
/// solution is tracked in b/33946428 and probably involves setting the
/// attribute on some data structure that represents a layer.
///
/// @param spec Buffer specification.
/// @param z_order Z order, higher values are displayed on top of lower ones,
///     the default value is 0.
void gvr_buffer_spec_set_z_order(gvr_buffer_spec* spec, int z_order);

/// Sets the initial visibility of the layer to be created.
/// Note that this API is a short-term workaround for SysUI work and is never
/// meant to graduate as is to either gvr.h or gvr_private.h. The proper
/// solution is tracked in b/33946428 and probably involves setting the
/// attribute on some data structure that represents a layer.
///
/// @param spec Buffer specification.
/// @param visibility Initial visibility of the layer, defaults to GVR_VISIBLE.
///     See enum gvr_visibility for possible values.
void gvr_buffer_spec_set_visibility(gvr_buffer_spec* spec,
                                    int32_t visibility);

/// Sets whether to blur layers below the layer to be created.
/// Blurring is applied only to visible layers and only when the layer is
/// visible.
/// Note that this API currently is only implemented by the DreamOS
/// implementation of GVR and is a no-op in other implementations.
/// TODO(b/33946428): investigate the proper way to surface this feature
/// to SysUI.
///
/// @param spec Buffer specification.
/// @param blur_behind whether to blur layers behind, defaults to
///     GVR_BLUR_BEHIND_TRUE. See enum gvr_blur_behind for possible values.
void gvr_buffer_spec_set_blur_behind(gvr_buffer_spec* spec,
                                     int32_t blur_behind);

// ************************************************************************** //
// *                     Daydream PlexEng experimental APIs                 * //
// ************************************************************************** //

// Registers a new performance event listener that will be invoked on points
// of interest. By default no event listener is attached.  If multiple event
// listeners are attached they will all be invoked.  Failures can be checked
// with gvr_get_error().
// @param out_handle The pointer to memory where a successfully created handle
//     will be written.
// @param gvr The context to register callbacks for.
// @param user_data The pointer that will be passed back on callbacks for
//     user_data.
// @param event_callback The callback to be invoked when an event is observed.
//     On performance events callback will be invoked with the
//     user_data passed here, the gvr_perf_event_callback_type, and a float
//     value (if applicable) or -1.f.
// @return Returns GVR_EXPERIMENTAL_ERROR_NONE if a handle was created,
//     GVR_EXPERIMENTAL_ERROR_UNIMPLEMENTED if this feature is disabled,
//     or GVR_EXPERIMENTAL_ERROR_INVALID_ARGUMENT if a null pointer was passed.
bool gvr_experimental_register_perf_event_callback(
    gvr_context* gvr, int* out_handle, void* user_data,
    void (*event_callback)(void*, int, float));

// Unregisters a previously registered callback by its handle. Failures can be
// checked with gvr_get_error().
// @param handle The handle which was returned when registering the callback.
// @return Returns GVR_EXPERIMENTAL_ERROR_NONE if callback was unregistered,
//     GVR_EXPERIMENTAL_ERROR_INVALID_ARGUMENT if the if the handle wasn't
//     previously
//     registered.  If this feature is not enabled it will return
//     GVR_EXPERIMENTAL_ERROR_UNIMPLEMENTED.
bool gvr_experimental_unregister_perf_event_callback(gvr_context* gvr,
                                                     int handle);

// ************************************************************************** //
// *                    GVR Analytics experimental APIs                     * //
// ************************************************************************** //
// TODO(b/31634289): These functions are experimental because their main client
// case is the performance monitoring HUD, whose form and function is still
// under development. Consequently, the analytics API may change as the HUD's
// needs become clearer.
//
// These functions will be moved into the main API (probably gvr_private.h) once
// the HUD is ready to be shipped as part of the SDK.
//
// Contacts: georgelu@

/// Returns whether the "Performance Monitoring" developer option is enabled.
///
/// @param user_prefs Pointer to the gvr_user_prefs object returned by
///     gvr_get_user_prefs.
/// @return True if the "Performance Monitoring" developer option is enabled.
bool gvr_user_prefs_get_performance_monitoring_enabled(
    const gvr_user_prefs* user_prefs);

// Opaque struct returned by gvr_get_analytics that can be queried through
// gvr_analytics_get* functions.
//
// Note: The struct is never actually defined since gvr_analytics is actually
// just a static_cast of a gvr_context, similar to how gvr_user_prefs works.
typedef struct gvr_analytics_ gvr_analytics;

// Returns an opaque struct that can be queried for analytics data. The returned
// struct remains valid as long as the context is valid.
//
// @param gvr Pointer to the current gvr_context instance.
// @return An opaque struct that can be queried through gvr_analytics_*
//     functions.
const gvr_analytics* gvr_get_analytics(gvr_context* gvr);

// If the "Performance Monitoring" developer option in VR settings is enabled,
// returns a gvr_analytics_sample* containing analytics data. Caller is
// responsible for calling gvr_analytics_destroy_sample on the returned object.
//
// @param analytics gvr_analytics* returned by gvr_get_analytics.
// @return gvr_analytics_sample* containing analytics data.
const gvr_analytics_sample* gvr_analytics_create_sample(
    const gvr_analytics* analytics);

// Returns pointer to a buffer containing a serialized AnalyticsSample proto.
// The buffer is valid only for the lifetime of the gvr_analytics_sample.
//
// @param Pointer to a gvr_analytics_sample object.
// @return Pointer to buffer.
const char* gvr_analytics_sample_get_buffer(const gvr_analytics_sample* sample);

// Returns the length of the buffer returned by gvr_analytics_sample_get_buffer.
//
// @param Pointer to a gvr_analytics_sample object.
// @return Length of buffer.
size_t gvr_analytics_sample_get_buffer_length(
    const gvr_analytics_sample* sample);

// Destroys a gvr_analytics_sample* previously created through
// gvr_analytics_create_sample.
//
// @param sample Pointer to pointer that will be set to null and whose
//     underlying gvr_analytics_sample will be destroyed.
void gvr_analytics_destroy_sample(const gvr_analytics_sample** sample);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // VR_GVR_CAPI_SRC_GVR_EXPERIMENTAL_H_
