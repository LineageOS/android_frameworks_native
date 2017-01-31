#ifndef VR_GVR_CAPI_SRC_GVR_TYPES_EXPERIMENTAL_H_
#define VR_GVR_CAPI_SRC_GVR_TYPES_EXPERIMENTAL_H_

#include <string>

// ************************************************************************** //
// *                     DaydreamOS experimental Types                * //
// ************************************************************************** //

// Visibility of a layer.
typedef enum {
  GVR_INVISIBLE = 0,
  GVR_VISIBLE = 1,
} gvr_visibility;

// Whether to blur layers behind a layer.
typedef enum {
  GVR_BLUR_BEHIND_FALSE = 0,
  GVR_BLUR_BEHIND_TRUE = 1,
} gvr_blur_behind;

// GVR external surface
typedef struct gvr_external_surface_ gvr_external_surface;

// ************************************************************************** //
// *                     Daydream PlexEng experimental Types                * //
// ************************************************************************** //

// Types of events that can have callbacks registered.
// If documented, type will return a payload value when called, or will
// otherwise be invoked with -1.f.
// This enum has to be duplicated because there is no way to include from
// /vr/gvr/render/performance_registry.h.  Duplicate changes made here there.
typedef enum {
  // Will be invoked with value -1.f.
  GVR_ON_ASYNC_REPROJECTION_FRAME_START = 0,
  // Will be invoked with value -1.f.
  GVR_ON_ASYNC_REPROJECTION_FRAME_STOP = 1,
  // When invoked will be called with how late in microseconds the frame was.
  GVR_ON_ASYNC_REPROJECTION_FRAME_DROP = 2,
  // The number of types of performance events you can have.
  // Also note that this value is considered invalid.
  GVR_NUM_PERF_EVENT_CALLBACK_TYPES = 3,
} gvr_perf_event_callback_type;

// Experimental VR-specific features which may or may not be supported on the
// underlying platform.  These values should not overlap with current or future
// gvr_feature values, so we're starting with 1000000 and increasing upward.
typedef enum {
  // Head tracking with 6 degrees of freedom (position & rotation)
  GVR_FEATURE_HEAD_POSE_6DOF = 1000000,
} gvr_experimental_feature;

// ************************************************************************** //
// *                    GVR Analytics experimental APIs                     * //
// ************************************************************************** //

// Opaque struct returned by gvr_analytics_create_sample, used to transmit an
// AnaylticsSample proto across the native layer.
typedef struct gvr_analytics_sample_ {
  // Serialized AnalyticsSample proto. Note that this is not a C string, meaning
  // it is not null-terminated and may contain non-terminating nulls.
  std::string serialized_proto;
} gvr_analytics_sample;

#endif  // VR_GVR_CAPI_SRC_GVR_TYPES_EXPERIMENTAL_H_
