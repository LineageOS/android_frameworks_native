#include "aidl/android/dvr/parcelable_composer_layer.h"

#include <binder/Parcel.h>
#include <ui/Fence.h>
#include <ui/GraphicBuffer.h>
#include <ui/GraphicBufferMapper.h>

namespace android {
namespace dvr {

ParcelableComposerLayer::ParcelableComposerLayer() {}

ParcelableComposerLayer::ParcelableComposerLayer(
    const ComposerView::ComposerLayer& layer) : layer_(layer) {}

ParcelableComposerLayer::~ParcelableComposerLayer() {}

status_t ParcelableComposerLayer::writeToParcel(Parcel* parcel) const {
  status_t ret = parcel->writeUint64(layer_.id);
  if (ret != OK) return ret;

  ret = parcel->write(*layer_.buffer);
  if (ret != OK) return ret;

  ret = parcel->writeBool(layer_.fence->isValid());
  if (ret != OK) return ret;

  if (layer_.fence->isValid()) {
    ret = parcel->writeFileDescriptor(layer_.fence->dup(), true);
    if (ret != OK) return ret;
  }

  ret = parcel->writeInt32(layer_.display_frame.left);
  if (ret != OK) return ret;

  ret = parcel->writeInt32(layer_.display_frame.top);
  if (ret != OK) return ret;

  ret = parcel->writeInt32(layer_.display_frame.right);
  if (ret != OK) return ret;

  ret = parcel->writeInt32(layer_.display_frame.bottom);
  if (ret != OK) return ret;

  ret = parcel->writeFloat(layer_.crop.left);
  if (ret != OK) return ret;

  ret = parcel->writeFloat(layer_.crop.top);
  if (ret != OK) return ret;

  ret = parcel->writeFloat(layer_.crop.right);
  if (ret != OK) return ret;

  ret = parcel->writeFloat(layer_.crop.bottom);
  if (ret != OK) return ret;

  ret = parcel->writeInt32(static_cast<int32_t>(layer_.blend_mode));
  if (ret != OK) return ret;

  ret = parcel->writeFloat(layer_.alpha);
  if (ret != OK) return ret;

  ret = parcel->writeUint32(layer_.type);
  if (ret != OK) return ret;

  ret = parcel->writeUint32(layer_.app_id);
  if (ret != OK) return ret;

  return OK;
}

status_t ParcelableComposerLayer::readFromParcel(const Parcel* parcel) {
  status_t ret = parcel->readUint64(&layer_.id);
  if (ret != OK) return ret;

  layer_.buffer = new GraphicBuffer();
  ret = parcel->read(*layer_.buffer);
  if (ret != OK) {
    layer_.buffer.clear();
    return ret;
  }

  bool has_fence = 0;
  ret = parcel->readBool(&has_fence);
  if (ret != OK) return ret;

  if (has_fence)
    layer_.fence = new Fence(dup(parcel->readFileDescriptor()));
  else
    layer_.fence = new Fence();

  ret = parcel->readInt32(&layer_.display_frame.left);
  if (ret != OK) return ret;

  ret = parcel->readInt32(&layer_.display_frame.top);
  if (ret != OK) return ret;

  ret = parcel->readInt32(&layer_.display_frame.right);
  if (ret != OK) return ret;

  ret = parcel->readInt32(&layer_.display_frame.bottom);
  if (ret != OK) return ret;

  ret = parcel->readFloat(&layer_.crop.left);
  if (ret != OK) return ret;

  ret = parcel->readFloat(&layer_.crop.top);
  if (ret != OK) return ret;

  ret = parcel->readFloat(&layer_.crop.right);
  if (ret != OK) return ret;

  ret = parcel->readFloat(&layer_.crop.bottom);
  if (ret != OK) return ret;

  ret = parcel->readInt32(reinterpret_cast<int32_t*>(&layer_.blend_mode));
  if (ret != OK) return ret;

  ret = parcel->readFloat(&layer_.alpha);
  if (ret != OK) return ret;

  ret = parcel->readUint32(&layer_.type);
  if (ret != OK) return ret;

  ret = parcel->readUint32(&layer_.app_id);
  if (ret != OK) return ret;

  return OK;
}

}  // namespace dvr
}  // namespace android
