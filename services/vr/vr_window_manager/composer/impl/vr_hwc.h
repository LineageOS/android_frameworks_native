/*
 * Copyright 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef VR_WINDOW_MANAGER_COMPOSER_IMPL_VR_HWC_H_
#define VR_WINDOW_MANAGER_COMPOSER_IMPL_VR_HWC_H_

#include <android/hardware/graphics/composer/2.1/IComposer.h>
#include <ComposerBase.h>
#include <ui/Fence.h>
#include <ui/GraphicBuffer.h>
#include <utils/StrongPointer.h>

#include <mutex>

#include "sync_timeline.h"

using namespace android::hardware::graphics::common::V1_0;
using namespace android::hardware::graphics::composer::V2_1;

using android::hardware::hidl_handle;
using android::hardware::hidl_string;
using android::hardware::hidl_vec;
using android::hardware::Return;
using android::hardware::Void;

namespace android {

class Fence;
class GraphicBuffer;

namespace dvr {

class VrComposerClient;

using android::hardware::graphics::common::V1_0::PixelFormat;
using android::hardware::graphics::composer::V2_1::implementation::ComposerBase;

class ComposerView {
 public:
  struct ComposerLayer {
    using Recti = hardware::graphics::composer::V2_1::IComposerClient::Rect;
    using Rectf = hardware::graphics::composer::V2_1::IComposerClient::FRect;
    using BlendMode =
        hardware::graphics::composer::V2_1::IComposerClient::BlendMode;

    // TODO(dnicoara): Add all layer properties. For now just the basics to get
    // it going.
    sp<GraphicBuffer> buffer;
    sp<Fence> fence;
    Recti display_frame;
    Rectf crop;
    BlendMode blend_mode;
    float alpha;
    uint32_t type;
    uint32_t app_id;
  };

  using Frame = std::vector<ComposerLayer>;

  class Observer {
   public:
    virtual ~Observer() {}

    // Returns a list of layers that need to be shown together. Layers are
    // returned in z-order, with the lowest layer first.
    virtual void OnNewFrame(const Frame& frame) = 0;
  };

  virtual ~ComposerView() {}

  virtual void RegisterObserver(Observer* observer) = 0;
  virtual void UnregisterObserver(Observer* observer) = 0;

  // Called to release the oldest frame received by the observer.
  virtual void ReleaseFrame() = 0;
};

struct HwcLayer {
  using Composition =
      hardware::graphics::composer::V2_1::IComposerClient::Composition;

  HwcLayer(Layer new_id) : id(new_id) {}

  Layer id;
  Composition composition_type;
  uint32_t z_order;
  ComposerView::ComposerLayer info;
};

class HwcDisplay {
 public:
  HwcDisplay();
  ~HwcDisplay();

  bool Initialize();

  HwcLayer* CreateLayer();
  bool DestroyLayer(Layer id);
  HwcLayer* GetLayer(Layer id);

  bool SetClientTarget(const native_handle_t* handle, base::unique_fd fence);

  void GetChangedCompositionTypes(
      std::vector<Layer>* layer_ids,
      std::vector<IComposerClient::Composition>* composition);

  Error GetFrame(std::vector<ComposerView::ComposerLayer>* out_frame);

  void GetReleaseFences(int* present_fence, std::vector<Layer>* layer_ids,
                        std::vector<int>* fences);

  void ReleaseFrame();

 private:
  // The client target buffer and the associated fence.
  // TODO(dnicoara): Replace this with a list of ComposerView::ComposerLayer.
  sp<GraphicBuffer> buffer_;
  sp<Fence> fence_;

  // List of currently active layers.
  std::vector<HwcLayer> layers_;

  // Layer ID generator.
  uint64_t layer_ids_ = 1;

  // Creates software sync fences used to signal releasing frames.
  SyncTimeline hwc_timeline_;

  // Keeps track of the current fence time. Used in conjunction with
  // |hwc_timeline_| to properly signal frame release times. Allows the observer
  // to receive multiple presentation frames without calling ReleaseFrame() in
  // between each presentation. When the observer is ready to release a frame
  // only the oldest presentation frame is affected by the release.
  int fence_time_ = 0;

  HwcDisplay(const HwcDisplay&) = delete;
  void operator=(const HwcDisplay&) = delete;
};

class VrHwc : public IComposer, public ComposerBase, public ComposerView {
 public:
  VrHwc();
  ~VrHwc() override;

  bool Initialize();

  bool hasCapability(Capability capability) const;

  Error setLayerInfo(Display display, Layer layer, uint32_t type,
                     uint32_t appId);

  // ComposerBase
  void removeClient() override;
  void enableCallback(bool enable) override;

  uint32_t getMaxVirtualDisplayCount() override;
  Error createVirtualDisplay(uint32_t width, uint32_t height,
      PixelFormat* format, Display* outDisplay) override;
  Error destroyVirtualDisplay(Display display) override;

  Error createLayer(Display display, Layer* outLayer) override;
  Error destroyLayer(Display display, Layer layer) override;

  Error getActiveConfig(Display display, Config* outConfig) override;
  Error getClientTargetSupport(Display display,
          uint32_t width, uint32_t height,
          PixelFormat format, Dataspace dataspace) override;
  Error getColorModes(Display display, hidl_vec<ColorMode>* outModes) override;
  Error getDisplayAttribute(Display display, Config config,
          IComposerClient::Attribute attribute, int32_t* outValue) override;
  Error getDisplayConfigs(Display display, hidl_vec<Config>* outConfigs) override;
  Error getDisplayName(Display display, hidl_string* outName) override;
  Error getDisplayType(Display display,
          IComposerClient::DisplayType* outType) override;
  Error getDozeSupport(Display display, bool* outSupport) override;
  Error getHdrCapabilities(Display display, hidl_vec<Hdr>* outTypes,
          float* outMaxLuminance, float* outMaxAverageLuminance,
          float* outMinLuminance) override;

  Error setActiveConfig(Display display, Config config) override;
  Error setColorMode(Display display, ColorMode mode) override;
  Error setPowerMode(Display display, IComposerClient::PowerMode mode) override;
  Error setVsyncEnabled(Display display, IComposerClient::Vsync enabled) override;

  Error setColorTransform(Display display, const float* matrix,
          int32_t hint) override;
  Error setClientTarget(Display display, buffer_handle_t target,
          int32_t acquireFence, int32_t dataspace,
          const std::vector<hwc_rect_t>& damage) override;
  Error setOutputBuffer(Display display, buffer_handle_t buffer,
          int32_t releaseFence) override;
  Error validateDisplay(Display display,
          std::vector<Layer>* outChangedLayers,
          std::vector<IComposerClient::Composition>* outCompositionTypes,
          uint32_t* outDisplayRequestMask,
          std::vector<Layer>* outRequestedLayers,
          std::vector<uint32_t>* outRequestMasks) override;
  Error acceptDisplayChanges(Display display) override;
  Error presentDisplay(Display display, int32_t* outPresentFence,
          std::vector<Layer>* outLayers,
          std::vector<int32_t>* outReleaseFences) override;

  Error setLayerCursorPosition(Display display, Layer layer,
          int32_t x, int32_t y) override;
  Error setLayerBuffer(Display display, Layer layer,
          buffer_handle_t buffer, int32_t acquireFence) override;
  Error setLayerSurfaceDamage(Display display, Layer layer,
          const std::vector<hwc_rect_t>& damage) override;
  Error setLayerBlendMode(Display display, Layer layer, int32_t mode) override;
  Error setLayerColor(Display display, Layer layer,
          IComposerClient::Color color) override;
  Error setLayerCompositionType(Display display, Layer layer,
          int32_t type) override;
  Error setLayerDataspace(Display display, Layer layer,
          int32_t dataspace) override;
  Error setLayerDisplayFrame(Display display, Layer layer,
          const hwc_rect_t& frame) override;
  Error setLayerPlaneAlpha(Display display, Layer layer, float alpha) override;
  Error setLayerSidebandStream(Display display, Layer layer,
          buffer_handle_t stream) override;
  Error setLayerSourceCrop(Display display, Layer layer,
          const hwc_frect_t& crop) override;
  Error setLayerTransform(Display display, Layer layer,
          int32_t transform) override;
  Error setLayerVisibleRegion(Display display, Layer layer,
          const std::vector<hwc_rect_t>& visible) override;
  Error setLayerZOrder(Display display, Layer layer, uint32_t z) override;

  // IComposer:
  Return<void> getCapabilities(getCapabilities_cb hidl_cb) override;
  Return<void> dumpDebugInfo(dumpDebugInfo_cb hidl_cb) override;
  Return<void> createClient(createClient_cb hidl_cb) override;

  // ComposerView:
  void RegisterObserver(Observer* observer) override;
  void UnregisterObserver(Observer* observer) override;
  void ReleaseFrame() override;

 private:
  wp<VrComposerClient> client_;
  sp<IComposerCallback> callbacks_;

  // Guard access to internal state from binder threads.
  std::mutex mutex_;

  HwcDisplay display_;

  Observer* observer_ = nullptr;

  VrHwc(const VrHwc&) = delete;
  void operator=(const VrHwc&) = delete;
};


ComposerView* GetComposerViewFromIComposer(
    hardware::graphics::composer::V2_1::IComposer* composer);

hardware::graphics::composer::V2_1::IComposer* HIDL_FETCH_IComposer(
    const char* name);

}  // namespace dvr
}  // namespace android

#endif  // VR_WINDOW_MANAGER_COMPOSER_IMPL_VR_HWC_H_
