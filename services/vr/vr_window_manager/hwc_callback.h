#ifndef VR_WINDOW_MANAGER_HWC_CALLBACK_H_
#define VR_WINDOW_MANAGER_HWC_CALLBACK_H_

#include <deque>
#include <functional>
#include <mutex>
#include <vector>

#include <android-base/unique_fd.h>
#include <impl/vr_composer_view.h>
#include <impl/vr_hwc.h>

namespace android {

class Fence;
class GraphicBuffer;

namespace dvr {

using Recti = ComposerView::ComposerLayer::Recti;
using Rectf = ComposerView::ComposerLayer::Rectf;

class HwcCallback : public VrComposerView::Callback {
 public:
  struct HwcLayer {
    enum LayerType : uint32_t {
      // These are from frameworks/base/core/java/android/view/WindowManager.java
      kSurfaceFlingerLayer = 0,
      kUndefinedWindow = ~0U,
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
      case kSurfaceFlingerLayer:
      case kUndefinedWindow:
        return true;
      default:
        return false;
      }
    }

    // This is a layer that provides some other functionality, eg dim layer.
    // We use this to determine the point at which layers are "on top".
    bool is_extra_layer() const {
      switch(type) {
      case kSurfaceFlingerLayer:
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
    virtual base::unique_fd OnFrame(std::unique_ptr<Frame>) = 0;
  };

  explicit HwcCallback(Client* client);
  ~HwcCallback() override;

 private:
  base::unique_fd OnNewFrame(const ComposerView::Frame& frame) override;

  Client *client_;

  HwcCallback(const HwcCallback&) = delete;
  void operator=(const HwcCallback&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // VR_WINDOW_MANAGER_HWC_CALLBACK_H_
