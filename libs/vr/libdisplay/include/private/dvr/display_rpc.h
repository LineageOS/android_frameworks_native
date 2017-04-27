#ifndef ANDROID_DVR_DISPLAY_RPC_H_
#define ANDROID_DVR_DISPLAY_RPC_H_

#include <sys/types.h>

#include <array>
#include <map>

#include <pdx/rpc/remote_method.h>
#include <pdx/rpc/serializable.h>
#include <pdx/rpc/variant.h>
#include <private/dvr/bufferhub_rpc.h>
#include <private/dvr/display_types.h>

namespace android {
namespace dvr {

struct SystemDisplayMetrics {
  uint32_t display_native_width;
  uint32_t display_native_height;
  uint32_t display_x_dpi;
  uint32_t display_y_dpi;
  uint32_t distorted_width;
  uint32_t distorted_height;
  uint32_t vsync_period_ns;
  uint32_t hmd_ipd_mm;
  float inter_lens_distance_m;
  std::array<float, 4> left_fov_lrbt;
  std::array<float, 4> right_fov_lrbt;

 private:
  PDX_SERIALIZABLE_MEMBERS(SystemDisplayMetrics, display_native_width,
                           display_native_height, display_x_dpi, display_y_dpi,
                           distorted_width, distorted_height, vsync_period_ns,
                           hmd_ipd_mm, inter_lens_distance_m, left_fov_lrbt,
                           right_fov_lrbt);
};

using SurfaceType = uint32_t;
struct SurfaceTypeEnum {
  enum : SurfaceType {
    Normal = DVR_SURFACE_TYPE_NORMAL,
    VideoMesh = DVR_SURFACE_TYPE_VIDEO_MESH,
    Overlay = DVR_SURFACE_TYPE_OVERLAY,
  };
};

using DisplaySurfaceFlags = uint32_t;
enum class DisplaySurfaceFlagsEnum : DisplaySurfaceFlags {
  DisableSystemEds = DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_EDS,
  DisableSystemDistortion = DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_DISTORTION,
  VerticalFlip = DVR_DISPLAY_SURFACE_FLAGS_VERTICAL_FLIP,
  SeparateGeometry = DVR_DISPLAY_SURFACE_FLAGS_GEOMETRY_SEPARATE_2,
  DisableSystemCac = DVR_DISPLAY_SURFACE_FLAGS_DISABLE_SYSTEM_CAC,
};

using DisplaySurfaceInfoFlags = uint32_t;
enum class DisplaySurfaceInfoFlagsEnum : DisplaySurfaceInfoFlags {
  BuffersChanged = DVR_DISPLAY_SURFACE_ITEM_FLAGS_BUFFERS_CHANGED,
};

using DisplaySurfaceAttributeValue =
    pdx::rpc::Variant<int32_t, int64_t, bool, float, std::array<float, 2>,
                      std::array<float, 3>, std::array<float, 4>,
                      std::array<float, 16>>;
using DisplaySurfaceAttribute = uint32_t;
struct DisplaySurfaceAttributeEnum {
  enum : DisplaySurfaceAttribute {
    ZOrder = DVR_DISPLAY_SURFACE_ATTRIBUTE_Z_ORDER,
    Visible = DVR_DISPLAY_SURFACE_ATTRIBUTE_VISIBLE,
    // Manager only.
    Blur = DVR_DISPLAY_SURFACE_ATTRIBUTE_BLUR,
    // Client only.
    ExcludeFromBlur = DVR_DISPLAY_SURFACE_ATTRIBUTE_EXCLUDE_FROM_BLUR,
    BlurBehind = DVR_DISPLAY_SURFACE_ATTRIBUTE_BLUR_BEHIND,
  };

  static std::string ToString(DisplaySurfaceAttribute attribute) {
    switch (attribute) {
      case ZOrder:
        return "z-order";
      case Visible:
        return "visible";
      case Blur:
        return "blur";
      case ExcludeFromBlur:
        return "exclude-from-blur";
      case BlurBehind:
        return "blur-behind";
      default:
        return "unknown";
    }
  }
};

using DisplaySurfaceAttributes =
    std::map<DisplaySurfaceAttribute, DisplaySurfaceAttributeValue>;

struct DisplaySurfaceInfo {
  int surface_id;
  int process_id;
  SurfaceType type;
  DisplaySurfaceFlags flags;
  DisplaySurfaceInfoFlags info_flags;
  DisplaySurfaceAttributes client_attributes;
  DisplaySurfaceAttributes manager_attributes;

  // Convenience accessors.
  bool IsClientVisible() const {
    const auto* variant =
        FindClientAttribute(DisplaySurfaceAttributeEnum::Visible);
    bool bool_value;
    if (variant && pdx::rpc::IfAnyOf<int32_t, int64_t, bool, float>::Get(
                       variant, &bool_value))
      return bool_value;
    else
      return false;
  }

  int ClientZOrder() const {
    const auto* variant =
        FindClientAttribute(DisplaySurfaceAttributeEnum::ZOrder);
    int int_value;
    if (variant &&
        pdx::rpc::IfAnyOf<int32_t, int64_t, float>::Get(variant, &int_value))
      return int_value;
    else
      return 0;
  }

 private:
  const DisplaySurfaceAttributeValue* FindClientAttribute(
      DisplaySurfaceAttribute key) const {
    auto search = client_attributes.find(key);
    return (search != client_attributes.end()) ? &search->second : nullptr;
  }

  PDX_SERIALIZABLE_MEMBERS(DisplaySurfaceInfo, surface_id, process_id, type,
                           flags, info_flags, client_attributes,
                           manager_attributes);
};

struct AlignmentMarker {
 public:
  float horizontal;
  float vertical;

  PDX_SERIALIZABLE_MEMBERS(AlignmentMarker, horizontal, vertical);
};

struct DaydreamInternalParams {
 public:
  int32_t version;
  std::vector<AlignmentMarker> alignment_markers;

  PDX_SERIALIZABLE_MEMBERS(DaydreamInternalParams, version, alignment_markers);
};

struct ViewerParams {
 public:
  // TODO(hendrikw): Do we need viewer_vendor_name and viewer_model_name?
  float screen_to_lens_distance;
  float inter_lens_distance;
  float screen_center_to_lens_distance;
  std::vector<float> left_eye_field_of_view_angles;

  enum VerticalAlignmentType : int32_t {
    BOTTOM = 0,  // phone rests against a fixed bottom tray
    CENTER = 1,  // phone screen assumed to be centered w.r.t. lenses
    TOP = 2      // phone rests against a fixed top tray
  };

  enum EyeOrientation : int32_t {
    kCCW0Degrees = 0,
    kCCW90Degrees = 1,
    kCCW180Degrees = 2,
    kCCW270Degrees = 3,
    kCCW0DegreesMirrored = 4,
    kCCW90DegreesMirrored = 5,
    kCCW180DegreesMirrored = 6,
    kCCW270DegreesMirrored = 7
  };

  VerticalAlignmentType vertical_alignment;
  std::vector<EyeOrientation> eye_orientations;

  float tray_to_lens_distance;

  std::vector<float> distortion_coefficients_r;
  std::vector<float> distortion_coefficients_g;
  std::vector<float> distortion_coefficients_b;

  DaydreamInternalParams daydream_internal;

  PDX_SERIALIZABLE_MEMBERS(ViewerParams, screen_to_lens_distance,
                           inter_lens_distance, screen_center_to_lens_distance,
                           left_eye_field_of_view_angles, vertical_alignment,
                           eye_orientations, tray_to_lens_distance,
                           distortion_coefficients_r, distortion_coefficients_g,
                           distortion_coefficients_b, daydream_internal);
};

struct DisplayRPC {
  // Service path.
  static constexpr char kClientPath[] = "system/vr/display/client";

  // Op codes.
  enum {
    kOpGetMetrics = 0,
    kOpGetEdsCapture,
    kOpCreateSurface,
    kOpCreateBufferQueue,
    kOpSetAttributes,
    kOpGetMetadataBuffer,
    kOpCreateVideoMeshSurface,
    kOpVideoMeshSurfaceCreateProducerQueue,
    kOpSetViewerParams,
    kOpGetNamedBuffer,
    kOpIsVrAppRunning,
  };

  // Aliases.
  using ByteBuffer = pdx::rpc::BufferWrapper<std::vector<uint8_t>>;
  using LocalChannelHandle = pdx::LocalChannelHandle;
  using Void = pdx::rpc::Void;

  // Methods.
  PDX_REMOTE_METHOD(GetMetrics, kOpGetMetrics, SystemDisplayMetrics(Void));
  PDX_REMOTE_METHOD(GetEdsCapture, kOpGetEdsCapture, ByteBuffer(Void));
  PDX_REMOTE_METHOD(CreateSurface, kOpCreateSurface,
                    int(int width, int height, int format, int usage,
                        DisplaySurfaceFlags flags));
  PDX_REMOTE_METHOD(CreateBufferQueue, kOpCreateBufferQueue,
                    LocalChannelHandle(Void));
  PDX_REMOTE_METHOD(SetAttributes, kOpSetAttributes,
                    int(const DisplaySurfaceAttributes& attributes));
  PDX_REMOTE_METHOD(GetMetadataBuffer, kOpGetMetadataBuffer,
                    LocalChannelHandle(Void));
  // VideoMeshSurface methods
  PDX_REMOTE_METHOD(CreateVideoMeshSurface, kOpCreateVideoMeshSurface,
                    LocalChannelHandle(Void));
  PDX_REMOTE_METHOD(VideoMeshSurfaceCreateProducerQueue,
                    kOpVideoMeshSurfaceCreateProducerQueue,
                    LocalChannelHandle(Void));
  PDX_REMOTE_METHOD(SetViewerParams, kOpSetViewerParams,
                    void(const ViewerParams& viewer_params));
  PDX_REMOTE_METHOD(GetNamedBuffer, kOpGetNamedBuffer,
                    LocalNativeBufferHandle(const std::string& name));
  PDX_REMOTE_METHOD(IsVrAppRunning, kOpIsVrAppRunning, int(Void));
};

struct DisplayManagerRPC {
  // Service path.
  static constexpr char kClientPath[] = "system/vr/display/manager";

  // Op codes.
  enum {
    kOpGetSurfaceList = 0,
    kOpUpdateSurfaces,
    kOpSetupNamedBuffer,
  };

  // Aliases.
  using LocalChannelHandle = pdx::LocalChannelHandle;
  using Void = pdx::rpc::Void;

  // Methods.
  PDX_REMOTE_METHOD(GetSurfaceList, kOpGetSurfaceList,
                    std::vector<DisplaySurfaceInfo>(Void));
  PDX_REMOTE_METHOD(
      UpdateSurfaces, kOpUpdateSurfaces,
      int(const std::map<int, DisplaySurfaceAttributes>& updates));
  PDX_REMOTE_METHOD(SetupNamedBuffer, kOpSetupNamedBuffer,
                    LocalNativeBufferHandle(const std::string& name,
                                            size_t size,
                                            uint64_t producer_usage,
                                            uint64_t consumer_usage));
};

struct ScreenshotData {
  int width;
  int height;
  std::vector<uint8_t> buffer;

 private:
  PDX_SERIALIZABLE_MEMBERS(ScreenshotData, width, height, buffer);
};

struct DisplayScreenshotRPC {
  // Service path.
  static constexpr char kClientPath[] = "system/vr/display/screenshot";

  // Op codes.
  enum {
    kOpGetFormat = 0,
    kOpTakeScreenshot,
  };

  using Void = pdx::rpc::Void;

  PDX_REMOTE_METHOD(GetFormat, kOpGetFormat, int(Void));
  PDX_REMOTE_METHOD(TakeScreenshot, kOpTakeScreenshot,
                    ScreenshotData(int layer_index));
};

struct VSyncSchedInfo {
  int64_t vsync_period_ns;
  int64_t timestamp_ns;
  uint32_t next_vsync_count;

 private:
  PDX_SERIALIZABLE_MEMBERS(VSyncSchedInfo, vsync_period_ns, timestamp_ns,
                           next_vsync_count);
};

struct DisplayVSyncRPC {
  // Service path.
  static constexpr char kClientPath[] = "system/vr/display/vsync";

  // Op codes.
  enum {
    kOpWait = 0,
    kOpAck,
    kOpGetLastTimestamp,
    kOpGetSchedInfo,
    kOpAcknowledge,
  };

  // Aliases.
  using Void = pdx::rpc::Void;
  using Timestamp = int64_t;

  // Methods.
  PDX_REMOTE_METHOD(Wait, kOpWait, Timestamp(Void));
  PDX_REMOTE_METHOD(GetLastTimestamp, kOpGetLastTimestamp, Timestamp(Void));
  PDX_REMOTE_METHOD(GetSchedInfo, kOpGetSchedInfo, VSyncSchedInfo(Void));
  PDX_REMOTE_METHOD(Acknowledge, kOpAcknowledge, int(Void));
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_DISPLAY_RPC_H_
