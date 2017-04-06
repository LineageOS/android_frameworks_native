#ifndef ANDROID_DVR_SERVICES_DISPLAYD_DISPLAY_SERVICE_H_
#define ANDROID_DVR_SERVICES_DISPLAYD_DISPLAY_SERVICE_H_

#include <pdx/service.h>
#include <private/dvr/buffer_hub_client.h>
#include <private/dvr/bufferhub_rpc.h>
#include <private/dvr/display_rpc.h>
#include <private/dvr/late_latch.h>

#include <functional>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include "acquired_buffer.h"
#include "display_surface.h"
#include "hardware_composer.h"

namespace android {
namespace dvr {

// DisplayService implements the displayd display service over ServiceFS.
class DisplayService : public pdx::ServiceBase<DisplayService> {
 public:
  bool IsInitialized() const override;
  std::string DumpState(size_t max_length) override;

  void OnChannelClose(pdx::Message& message,
                      const std::shared_ptr<pdx::Channel>& channel) override;
  pdx::Status<void> HandleMessage(pdx::Message& message) override;

  std::shared_ptr<DisplaySurface> GetDisplaySurface(int surface_id) const;
  std::vector<std::shared_ptr<DisplaySurface>> GetDisplaySurfaces() const;
  std::vector<std::shared_ptr<DisplaySurface>> GetVisibleDisplaySurfaces()
      const;

  // Updates the list of actively displayed surfaces. This must be called after
  // any change to client/manager attributes that affect visibility or z order.
  void UpdateActiveDisplaySurfaces();

  pdx::Status<BorrowedNativeBufferHandle> SetupNamedBuffer(
      const std::string& name, size_t size, int producer_usage,
      int consumer_usage);

  template <class A>
  void ForEachDisplaySurface(A action) const {
    ForEachChannel([action](const ChannelIterator::value_type& pair) mutable {
      auto surface = std::static_pointer_cast<SurfaceChannel>(pair.second);
      if (surface->type() == SurfaceTypeEnum::Normal)
        action(std::static_pointer_cast<DisplaySurface>(surface));
    });
  }

  using DisplayConfigurationUpdateNotifier = std::function<void(void)>;
  void SetDisplayConfigurationUpdateNotifier(
      DisplayConfigurationUpdateNotifier notifier);

  using VSyncCallback = HardwareComposer::VSyncCallback;
  void SetVSyncCallback(VSyncCallback callback) {
    hardware_composer_.SetVSyncCallback(callback);
  }

  HWCDisplayMetrics GetDisplayMetrics() {
    return hardware_composer_.display_metrics();
  }

  void GrantDisplayOwnership() { hardware_composer_.Enable(); }
  void SeizeDisplayOwnership() { hardware_composer_.Disable(); }

  void OnHardwareComposerRefresh();

 private:
  friend BASE;
  friend DisplaySurface;

  friend class VrDisplayStateService;

  DisplayService();
  DisplayService(android::Hwc2::Composer* hidl);

  SystemDisplayMetrics OnGetMetrics(pdx::Message& message);
  int OnCreateSurface(pdx::Message& message, int width, int height, int format,
                      int usage, DisplaySurfaceFlags flags);

  DisplayRPC::ByteBuffer OnGetEdsCapture(pdx::Message& message);

  void OnSetViewerParams(pdx::Message& message,
                         const ViewerParams& view_params);
  pdx::Status<BorrowedNativeBufferHandle> OnGetNamedBuffer(
      pdx::Message& message, const std::string& name);

  // Temporary query for current VR status. Will be removed later.
  int IsVrAppRunning(pdx::Message& message);

  // Called by DisplaySurface to signal that a surface property has changed and
  // the display manager should be notified.
  void NotifyDisplayConfigurationUpdate();

  pdx::Status<void> HandleSurfaceMessage(pdx::Message& message);

  DisplayService(const DisplayService&) = delete;
  void operator=(const DisplayService&) = delete;

  HardwareComposer hardware_composer_;
  DisplayConfigurationUpdateNotifier update_notifier_;

  std::unordered_map<std::string, std::unique_ptr<IonBuffer>> named_buffers_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SERVICES_DISPLAYD_DISPLAY_SERVICE_H_
