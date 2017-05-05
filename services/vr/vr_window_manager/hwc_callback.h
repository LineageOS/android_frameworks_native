#ifndef VR_WINDOW_MANAGER_HWC_CALLBACK_H_
#define VR_WINDOW_MANAGER_HWC_CALLBACK_H_

#include <android/dvr/BnVrComposerCallback.h>
#include <android-base/unique_fd.h>
#include <impl/vr_hwc.h>

#include <deque>
#include <functional>
#include <mutex>
#include <vector>

namespace android {

class Fence;
class GraphicBuffer;

namespace dvr {

using Recti = ComposerView::ComposerLayer::Recti;
using Rectf = ComposerView::ComposerLayer::Rectf;

class HwcCallback : public BnVrComposerCallback {
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

    void PrintLayer();

    sp<Fence> fence;
    sp<GraphicBuffer> buffer;
    Rectf crop;
    Recti display_frame;
    int32_t blending;
    uint32_t appid;
    LayerType type;
    float alpha;
    int32_t cursor_x;
    int32_t cursor_y;
    IComposerClient::Color color;
    int32_t dataspace;
    int32_t transform;
  };

  enum class FrameStatus {
    kUnfinished,
    kFinished,
    kError
  };

  class Frame {
  public:
    Frame(std::vector<HwcLayer>&& layers, uint32_t display_id, bool removed,
          int32_t display_width, int32_t display_height);

    FrameStatus Finish();
    const std::vector<HwcLayer>& layers() const { return layers_; }
    uint32_t display_id() const { return display_id_; }
    bool removed() const { return removed_; }
    int32_t display_width() const { return display_width_; }
    int32_t display_height() const { return display_height_; }

  private:
    uint32_t display_id_;
    bool removed_;
    int32_t display_width_;
    int32_t display_height_;
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
  binder::Status onNewFrame(const ParcelableComposerFrame& frame,
                            ParcelableUniqueFd* fence) override;

  Client *client_;

  HwcCallback(const HwcCallback&) = delete;
  void operator=(const HwcCallback&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // VR_WINDOW_MANAGER_HWC_CALLBACK_H_
