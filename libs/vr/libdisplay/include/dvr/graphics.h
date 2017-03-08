#ifndef DVR_GRAPHICS_H_
#define DVR_GRAPHICS_H_

#include <EGL/egl.h>
#include <sys/cdefs.h>

#ifdef __ARM_NEON
#include <arm_neon.h>
#else
#ifndef __FLOAT32X4T_86
#define __FLOAT32X4T_86
typedef float float32x4_t __attribute__ ((__vector_size__ (16)));
typedef struct float32x4x4_t { float32x4_t val[4]; };
#endif
#endif

#ifndef VK_USE_PLATFORM_ANDROID_KHR
#define VK_USE_PLATFORM_ANDROID_KHR 1
#endif
#include <vulkan/vulkan.h>

__BEGIN_DECLS

// Display surface parameters used to specify display surface options.
enum {
  DVR_SURFACE_PARAMETER_NONE = 0,
  // WIDTH
  DVR_SURFACE_PARAMETER_WIDTH_IN,
  // HEIGHT
  DVR_SURFACE_PARAMETER_HEIGHT_IN,
  // DISABLE_DISTORTION
  DVR_SURFACE_PARAMETER_DISABLE_DISTORTION_IN,
  // DISABLE_STABILIZATION
  DVR_SURFACE_PARAMETER_DISABLE_STABILIZATION_IN,
  // Disable chromatic aberration correction
  DVR_SURFACE_PARAMETER_DISABLE_CAC_IN,
  // ENABLE_LATE_LATCH: Enable late latching of pose data for application
  // GPU shaders.
  DVR_SURFACE_PARAMETER_ENABLE_LATE_LATCH_IN,
  // VISIBLE
  DVR_SURFACE_PARAMETER_VISIBLE_IN,
  // Z_ORDER
  DVR_SURFACE_PARAMETER_Z_ORDER_IN,
  // EXCLUDE_FROM_BLUR
  DVR_SURFACE_PARAMETER_EXCLUDE_FROM_BLUR_IN,
  // BLUR_BEHIND
  DVR_SURFACE_PARAMETER_BLUR_BEHIND_IN,
  // DISPLAY_WIDTH
  DVR_SURFACE_PARAMETER_DISPLAY_WIDTH_OUT,
  // DISPLAY_HEIGHT
  DVR_SURFACE_PARAMETER_DISPLAY_HEIGHT_OUT,
  // SURFACE_WIDTH: Returns width of allocated surface buffer.
  DVR_SURFACE_PARAMETER_SURFACE_WIDTH_OUT,
  // SURFACE_HEIGHT: Returns height of allocated surface buffer.
  DVR_SURFACE_PARAMETER_SURFACE_HEIGHT_OUT,
  // INTER_LENS_METERS: Returns float value in meters, the distance between
  // lenses.
  DVR_SURFACE_PARAMETER_INTER_LENS_METERS_OUT,
  // LEFT_FOV_LRBT: Return storage must have room for array of 4 floats (in
  // radians). The layout is left, right, bottom, top as indicated by LRBT.
  DVR_SURFACE_PARAMETER_LEFT_FOV_LRBT_OUT,
  // RIGHT_FOV_LRBT: Return storage must have room for array of 4 floats (in
  // radians). The layout is left, right, bottom, top as indicated by LRBT.
  DVR_SURFACE_PARAMETER_RIGHT_FOV_LRBT_OUT,
  // VSYNC_PERIOD: Returns the period of the display refresh (in
  // nanoseconds per refresh), as a 64-bit unsigned integer.
  DVR_SURFACE_PARAMETER_VSYNC_PERIOD_OUT,
  // SURFACE_TEXTURE_TARGET_TYPE: Returns the type of texture used as the render
  // target.
  DVR_SURFACE_PARAMETER_SURFACE_TEXTURE_TARGET_TYPE_OUT,
  // SURFACE_TEXTURE_TARGET_ID: Returns the texture ID used as the render
  // target.
  DVR_SURFACE_PARAMETER_SURFACE_TEXTURE_TARGET_ID_OUT,
  // Whether the surface needs to be flipped vertically before display. Default
  // is 0.
  DVR_SURFACE_PARAMETER_VERTICAL_FLIP_IN,
  // A bool indicating whether or not to create a GL context for the surface.
  // 0: don't create a context
  // Non-zero: create a context.
  // Default is 1.
  // If this value is 0, there must be a GLES 3.2 or greater context bound on
  // the current thread at the time dvrGraphicsContextCreate is called.
  DVR_SURFACE_PARAMETER_CREATE_GL_CONTEXT_IN,
  // Specify one of DVR_SURFACE_GEOMETRY_*.
  DVR_SURFACE_PARAMETER_GEOMETRY_IN,
  // FORMAT: One of DVR_SURFACE_FORMAT_RGBA_8888 or DVR_SURFACE_FORMAT_RGB_565.
  // Default is DVR_SURFACE_FORMAT_RGBA_8888.
  DVR_SURFACE_PARAMETER_FORMAT_IN,
  // GRAPHICS_API: One of DVR_SURFACE_GRAPHICS_API_GLES or
  // DVR_SURFACE_GRAPHICS_API_VULKAN. Default is GLES.
  DVR_SURFACE_PARAMETER_GRAPHICS_API_IN,
  // VK_INSTANCE: In Vulkan mode, the application creates a VkInstance and
  // passes it in.
  DVR_SURFACE_PARAMETER_VK_INSTANCE_IN,
  // VK_PHYSICAL_DEVICE: In Vulkan mode, the application passes in the
  // PhysicalDevice handle corresponding to the logical device passed to
  // VK_DEVICE.
  DVR_SURFACE_PARAMETER_VK_PHYSICAL_DEVICE_IN,
  // VK_DEVICE: In Vulkan mode, the application creates a VkDevice and
  // passes it in.
  DVR_SURFACE_PARAMETER_VK_DEVICE_IN,
  // VK_PRESENT_QUEUE: In Vulkan mode, the application selects a
  // presentation-compatible VkQueue and passes it in.
  DVR_SURFACE_PARAMETER_VK_PRESENT_QUEUE_IN,
  // VK_PRESENT_QUEUE_FAMILY: In Vulkan mode, the application passes in the
  // index of the queue family containing the VkQueue passed to
  // VK_PRESENT_QUEUE.
  DVR_SURFACE_PARAMETER_VK_PRESENT_QUEUE_FAMILY_IN,
  // VK_SWAPCHAIN_IMAGE_COUNT: In Vulkan mode, the number of swapchain images
  // will be returned here.
  DVR_SURFACE_PARAMETER_VK_SWAPCHAIN_IMAGE_COUNT_OUT,
  // VK_SWAPCHAIN_IMAGE_FORMAT: In Vulkan mode, the VkFormat of the swapchain
  // images will be returned here.
  DVR_SURFACE_PARAMETER_VK_SWAPCHAIN_IMAGE_FORMAT_OUT,
};

enum {
  // Default surface type. One wide buffer with the left eye view in the left
  // half and the right eye view in the right half.
  DVR_SURFACE_GEOMETRY_SINGLE,
  // Separate buffers, one per eye. The width parameters still refer to the
  // total width (2 * eye view width).
  DVR_SURFACE_GEOMETRY_SEPARATE_2,
};

// Surface format. Gvr only supports RGBA_8888 and RGB_565 for now, so those are
// the only formats we provide here.
enum {
  DVR_SURFACE_FORMAT_RGBA_8888,
  DVR_SURFACE_FORMAT_RGB_565,
};

enum {
  // Graphics contexts are created for OpenGL ES client applications by default.
  DVR_GRAPHICS_API_GLES,
  // Create the graphics context for Vulkan client applications.
  DVR_GRAPHICS_API_VULKAN,
};

#define DVR_SURFACE_PARAMETER_IN(name, value) \
  { DVR_SURFACE_PARAMETER_##name##_IN, (value), NULL }
#define DVR_SURFACE_PARAMETER_OUT(name, value) \
  { DVR_SURFACE_PARAMETER_##name##_OUT, 0, (value) }
#define DVR_SURFACE_PARAMETER_LIST_END \
  { DVR_SURFACE_PARAMETER_NONE, 0, NULL }

struct DvrSurfaceParameter {
  int32_t key;
  int64_t value;
  void* value_out;
};

// This is a convenience struct to hold the relevant information of the HMD
// lenses.
struct DvrLensInfo {
  float inter_lens_meters;
  float left_fov[4];
  float right_fov[4];
};

int dvrGetNativeDisplayDimensions(int* native_width, int* native_height);

// Opaque struct that represents a graphics context, the texture swap chain,
// and surfaces.
typedef struct DvrGraphicsContext DvrGraphicsContext;

// Create the graphics context. with the given parameters. The list of
// parameters is terminated with an entry where key ==
// DVR_SURFACE_PARAMETER_NONE. For example, the parameters array could be built
// as follows:
//   int display_width = 0, display_height = 0;
//   int surface_width = 0, surface_height = 0;
//   float inter_lens_meters = 0.0f;
//   float left_fov[4] = {0.0f};
//   float right_fov[4] = {0.0f};
//   int disable_warp = 0;
//   DvrSurfaceParameter surface_params[] = {
//       DVR_SURFACE_PARAMETER_IN(DISABLE_DISTORTION, disable_warp),
//       DVR_SURFACE_PARAMETER_OUT(DISPLAY_WIDTH, &display_width),
//       DVR_SURFACE_PARAMETER_OUT(DISPLAY_HEIGHT, &display_height),
//       DVR_SURFACE_PARAMETER_OUT(SURFACE_WIDTH, &surface_width),
//       DVR_SURFACE_PARAMETER_OUT(SURFACE_HEIGHT, &surface_height),
//       DVR_SURFACE_PARAMETER_OUT(INTER_LENS_METERS, &inter_lens_meters),
//       DVR_SURFACE_PARAMETER_OUT(LEFT_FOV_LRBT, left_fov),
//       DVR_SURFACE_PARAMETER_OUT(RIGHT_FOV_LRBT, right_fov),
//       DVR_SURFACE_PARAMETER_LIST_END,
//   };
int dvrGraphicsContextCreate(struct DvrSurfaceParameter* parameters,
                             DvrGraphicsContext** return_graphics_context);

// Destroy the graphics context.
void dvrGraphicsContextDestroy(DvrGraphicsContext* graphics_context);

// For every frame a schedule is decided by the system compositor. A sample
// schedule for two frames is shown below.
//
// |                        |                        |
// |-----------------|------|-----------------|------|
// |                        |                        |
// V0                A1     V1                A2     V2
//
// V0, V1, and V2 are display vsync events. Vsync events are uniquely identified
// throughout the DVR system by a vsync count maintained by the system
// compositor.
//
// A1 and A2 indicate when the application should finish rendering its frame,
// including all GPU work. Under normal circumstances the scheduled finish
// finish time will be set a few milliseconds before the vsync time, to give the
// compositor time to perform distortion and EDS on the app's buffer. For apps
// that don't use system distortion the scheduled frame finish time will be
// closer to the vsync time. Other factors can also effect the scheduled frame
// finish time, e.g. whether or not the System UI is being displayed.
typedef struct DvrFrameSchedule {
  // vsync_count is used as a frame identifier.
  uint32_t vsync_count;

  // The time when the app should finish rendering its frame, including all GPU
  // work.
  int64_t scheduled_frame_finish_ns;
} DvrFrameSchedule;

// Sleep until it's time to render the next frame. This should be the first
// function called as part of an app's render loop, which normally looks like
// this:
//
// while (1) {
//   DvrFrameSchedule schedule;
//   dvrGraphicsWaitNextFrame(..., &schedule); // Sleep until it's time to
//                                             // render the next frame
//   pose = dvrPoseGet(schedule.vsync_count);
//   dvrBeginRenderFrame(...);
//   <render a frame using the pose>
//   dvrPresent(...); // Post the buffer
// }
//
// |start_delay_ns| adjusts how long this function blocks the app from starting
// its next frame. If |start_delay_ns| is 0, the function waits until the
// scheduled frame finish time for the current frame, which gives the app one
// full vsync period to render the next frame. If the app needs less than a full
// vysnc period to render the frame, pass in a non-zero |start_delay_ns| to
// delay the start of frame rendering further. For example, if the vsync period
// is 11.1ms and the app takes 6ms to render a frame, consider setting this to
// 5ms (note that the value is in nanoseconds, so 5,000,000ns) so that the app
// finishes the frame closer to the scheduled frame finish time. Delaying the
// start of rendering allows the app to use a more up-to-date pose for
// rendering.
// |start_delay_ns| must be a positive value or 0. If you're unsure what to set
// for |start_delay_ns|, use 0.
//
// |out_next_frame_schedule| is an output parameter that will contain the
// schedule for the next frame. It can be null. This function returns a negative
// error code on failure.
int dvrGraphicsWaitNextFrame(DvrGraphicsContext* graphics_context,
                             int64_t start_delay_ns,
                             DvrFrameSchedule* out_next_frame_schedule);

// Prepares the graphics context's texture for rendering.  This function should
// be called once for each frame, ideally immediately before the first GL call
// on the framebuffer which wraps the surface texture.
//
// For GL contexts, GL states are modified as follows by this function:
// glBindTexture(GL_TEXTURE_2D, 0);
//
// @param[in] graphics_context The DvrGraphicsContext.
// @param[in] render_pose_orientation Head pose orientation that rendering for
//            this frame will be based off of. This must be an unmodified value
//            from DvrPoseAsync, returned by dvrPoseGet.
// @param[in] render_pose_translation Head pose translation that rendering for
//            this frame will be based off of. This must be an unmodified value
//            from DvrPoseAsync, returned by dvrPoseGet.
// @return 0 on success or a negative error code on failure.
// Check GL errors with glGetError for other error conditions.
int dvrBeginRenderFrameEds(DvrGraphicsContext* graphics_context,
                           float32x4_t render_pose_orientation,
                           float32x4_t render_pose_translation);
int dvrBeginRenderFrameEdsVk(DvrGraphicsContext* graphics_context,
                             float32x4_t render_pose_orientation,
                             float32x4_t render_pose_translation,
                             VkSemaphore acquire_semaphore,
                             VkFence acquire_fence,
                             uint32_t* swapchain_image_index,
                             VkImageView* swapchain_image_view);
// Same as dvrBeginRenderFrameEds, but with no EDS (asynchronous reprojection).
//
// For GL contexts, GL states are modified as follows by this function:
// glBindTexture(GL_TEXTURE_2D, 0);
//
// @param[in] graphics_context The DvrGraphicsContext.
// @return 0 on success or a negative error code on failure.
// Check GL errors with glGetError for other error conditions.
int dvrBeginRenderFrame(DvrGraphicsContext* graphics_context);
int dvrBeginRenderFrameVk(DvrGraphicsContext* graphics_context,
                          VkSemaphore acquire_semaphore, VkFence acquire_fence,
                          uint32_t* swapchain_image_index,
                          VkImageView* swapchain_image_view);

// Maximum number of views per surface buffer (for multiview, multi-eye, etc).
#define DVR_GRAPHICS_SURFACE_MAX_VIEWS 4

// Output data format of late latch shader. The application can bind all or part
// of this data with the buffer ID returned by dvrBeginRenderFrameLateLatch.
// This struct is compatible with std140 layout for use from shaders.
struct __attribute__((__packed__)) DvrGraphicsLateLatchData {
  // Column-major order.
  float view_proj_matrix[DVR_GRAPHICS_SURFACE_MAX_VIEWS][16];
  // Column-major order.
  float view_matrix[DVR_GRAPHICS_SURFACE_MAX_VIEWS][16];
  // Quaternion for pose orientation from start space.
  float pose_orientation[4];
  // Pose translation from start space.
  float pose_translation[4];
};

// Begin render frame with late latching of pose data. This kicks off a compute
// shader that will read the latest head pose and then compute and output
// matrices that can be used by application shaders.
//
// Matrices are computed with the following pseudo code.
//   Pose pose = getLateLatchPose();
//   out.pose_orientation = pose.orientation;
//   out.pose_translation = pose.translation;
//   mat4 head_from_center = ComputeInverseMatrix(pose);
//   for each view:
//     out.viewMatrix[view] =
//         eye_from_head_matrices[view] * head_from_center *
//         pose_offset_matrices[view];
//     out.viewProjMatrix[view] =
//         projection_matrices[view] * out.viewMatrix[view];
//
// For GL contexts, GL states are modified as follows by this function:
// glBindTexture(GL_TEXTURE_2D, 0);
// glBindBufferBase(GL_SHADER_STORAGE_BUFFER, 0, 0);
// glBindBufferBase(GL_SHADER_STORAGE_BUFFER, 1, 0);
// glBindBufferBase(GL_SHADER_STORAGE_BUFFER, 2, 0);
// glBindBufferBase(GL_SHADER_STORAGE_BUFFER, 3, 0);
// glUseProgram(0);
//
// @param[in] graphics_context The DvrGraphicsContext.
// @param[in] flags Specify 0.
// @param[in] target_vsync_count The target vsync count that this frame will
//            display at. This is used for pose prediction.
// @param[in] num_views Number of matrices in each of the following matrix array
//            parameters. Typically 2 for left and right eye views. Maximum is
//            DVR_GRAPHICS_SURFACE_MAX_VIEWS.
// @param[in] projection_matrices Array of pointers to |num_views| matrices with
//            column-major layout. These are the application projection
//            matrices.
// @param[in] eye_from_head_matrices Array of pointers to |num_views| matrices
//            with column-major layout. See pseudo code for how these are used.
// @param[in] pose_offset_matrices Array of pointers to |num_views| matrices
//            with column-major layout. See pseudo code for how these are used.
// @param[out] out_late_latch_buffer_id The GL buffer ID of the output buffer of
//             of type DvrGraphicsLateLatchData.
// @return 0 on success or a negative error code on failure.
// Check GL errors with glGetError for other error conditions.
int dvrBeginRenderFrameLateLatch(DvrGraphicsContext* graphics_context,
                                 uint32_t flags, uint32_t target_vsync_count,
                                 int num_views,
                                 const float** projection_matrices,
                                 const float** eye_from_head_matrices,
                                 const float** pose_offset_matrices,
                                 uint32_t* out_late_latch_buffer_id);

// Present a frame for display.
// This call is normally non-blocking, unless the internal buffer queue is full.
// @return 0 on success or a negative error code on failure.
int dvrPresent(DvrGraphicsContext* graphics_context);
int dvrPresentVk(DvrGraphicsContext* graphics_context,
                 VkSemaphore submit_semaphore, uint32_t swapchain_image_index);

// Post the next buffer early. This allows the application to race with either
// the async EDS process or the scanline for applications that are not using
// system distortion. When this is called, the next buffer in the queue is
// posted for display. It is up to the application to kick its GPU rendering
// work in time. If the rendering is incomplete there will be significant,
// undesirable tearing artifacts.
// It is not recommended to use this feature with system distortion.
void dvrGraphicsPostEarly(DvrGraphicsContext* graphics_context);

// Used to retrieve frame measurement timings from dvrGetFrameScheduleResults().
typedef struct DvrFrameScheduleResult {
  // vsync_count is used as a frame identifier.
  uint32_t vsync_count;

  // The app's scheduled frame finish time.
  int64_t scheduled_frame_finish_ns;

  // The difference (in nanoseconds) between the scheduled finish time and the
  // actual finish time.
  //
  // A value of +2ms for frame_finish_offset_ns indicates the app's frame was
  // late and may have been skipped by the compositor for that vsync. A value of
  // -1ms indicates the app's frame finished just ahead of schedule, as
  // desired. A value of -6ms indicates the app's frame finished well ahead of
  // schedule for that vsync. In that case the app may have unnecessary visual
  // latency. Consider using the start_delay_ns parameter in
  // dvrGraphicsWaitNextFrame() to align the app's frame finish time closer to
  // the scheduled finish time.
  int64_t frame_finish_offset_ns;
} DvrFrameScheduleResult;

// Retrieve the latest frame schedule results for the app. To collect all the
// results this should be called each frame. The results for each frame are
// returned only once.
// The number of results written to |results| is returned on success, or a
// negative error code on failure.
// |graphics_context| is the context to retrieve frame schedule results for.
// |results| is an array that will contain the frame schedule results.
// |result_count| is the size of the |results| array. It's recommended to pass
// in an array with 2 elements to ensure results for all frames are collected.
int dvrGetFrameScheduleResults(DvrGraphicsContext* graphics_context,
                               DvrFrameScheduleResult* results,
                               int result_count);

// Make the surface visible or hidden based on |visible|.
// 0: hidden, Non-zero: visible.
void dvrGraphicsSurfaceSetVisible(DvrGraphicsContext* graphics_context,
                                  int visible);

// Returns surface visilibity last requested by the client.
int dvrGraphicsSurfaceGetVisible(DvrGraphicsContext* graphics_context);

// Returns surface z order last requested by the client.
int dvrGraphicsSurfaceGetZOrder(DvrGraphicsContext* graphics_context);

// Sets the compositor z-order of the surface. Higher values display on
// top of lower values.
void dvrGraphicsSurfaceSetZOrder(DvrGraphicsContext* graphics_context,
                                 int z_order);

typedef struct DvrVideoMeshSurface DvrVideoMeshSurface;

DvrVideoMeshSurface* dvrGraphicsVideoMeshSurfaceCreate(
    DvrGraphicsContext* graphics_context);
void dvrGraphicsVideoMeshSurfaceDestroy(DvrVideoMeshSurface* surface);

// Present a VideoMeshSurface with the current video mesh transfromation matrix.
void dvrGraphicsVideoMeshSurfacePresent(DvrGraphicsContext* graphics_context,
                                        DvrVideoMeshSurface* surface,
                                        const int eye,
                                        const float* transform);

__END_DECLS

#endif  // DVR_GRAPHICS_H_
