#ifndef VR_WINDOW_MANAGER_HWC_CALLBACK_H_
#define VR_WINDOW_MANAGER_HWC_CALLBACK_H_

#include <deque>
#include <functional>
#include <mutex>
#include <vector>

#include <android/dvr/composer/1.0/IVrComposerCallback.h>
#include <android/dvr/composer/1.0/IVrComposerView.h>
#include <impl/vr_hwc.h>

namespace android {

class Fence;
class GraphicBuffer;

namespace dvr {

using Recti = ComposerView::ComposerLayer::Recti;
using Rectf = ComposerView::ComposerLayer::Rectf;

using composer::V1_0::IVrComposerCallback;
using composer::V1_0::IVrComposerView;

class HwcCallback : public IVrComposerCallback {
 public:
  struct HwcLayer {
    enum LayerType : uint32_t {
      // These are from frameworks/base/core/java/android/view/WindowManager.java
      kUndefinedWindow = 0,
      kFirstApplicationWindow = 1,
      kLastApplicationWindow = 99,
      kFirstSubWindow = 1000,
      kLastSubWindow = 1999,
      kFirstSystemWindow = 2000,
      kStatusBar = kFirstSystemWindow,
      kInputMethod = kFirstSystemWindow + 11,
      kNavigationBar = kFirstSystemWindow + 19,
      kLastSystemWindow = 2999,
    };

    bool should_skip_layer() const {
      switch (type) {
        // Always skip the following layer types
      case kNavigationBar:
      case kStatusBar:
      case kUndefinedWindow:
        return true;
      default:
        return false;
      }
    }

    sp<Fence> fence;
    sp<GraphicBuffer> buffer;
    Rectf crop;
    Recti display_frame;
    int32_t blending;
    uint32_t appid;
    LayerType type;
    float alpha;
  };

  enum class FrameStatus {
    kUnfinished,
    kFinished,
    kError
  };

  class Frame {
  public:
    Frame(std::vector<HwcLayer>&& layers);

    FrameStatus Finish();
    const std::vector<HwcLayer>& layers() const { return layers_; }

  private:
    std::vector<HwcLayer> layers_;
    FrameStatus status_ = FrameStatus::kUnfinished;
  };

  class Client {
   public:
    virtual ~Client() {}
    virtual void OnFrame(std::unique_ptr<Frame>) = 0;
  };

  explicit HwcCallback(IVrComposerView* composer_view, Client* client);
  ~HwcCallback() override;

 private:
  // This is the only method called on the binder thread. Everything else is
  // called on the render thread.
  Return<void> onNewFrame(const hidl_vec<IVrComposerCallback::Layer>& frame)
      override;

  IVrComposerView* composer_view_;
  Client *client_;
  std::mutex mutex_;


  HwcCallback(const HwcCallback&) = delete;
  void operator=(const HwcCallback&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // VR_WINDOW_MANAGER_HWC_CALLBACK_H_
