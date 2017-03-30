#include "aidl/android/dvr/parcelable_composer_frame.h"

#include <binder/Parcel.h>

#include "aidl/android/dvr/parcelable_composer_layer.h"

namespace android {
namespace dvr {

ParcelableComposerFrame::ParcelableComposerFrame() {}

ParcelableComposerFrame::ParcelableComposerFrame(
    const ComposerView::Frame& frame)
    : frame_(frame) {}

ParcelableComposerFrame::~ParcelableComposerFrame() {}

status_t ParcelableComposerFrame::writeToParcel(Parcel* parcel) const {
  status_t ret = parcel->writeUint64(frame_.display_id);
  if (ret != OK) return ret;

  ret = parcel->writeInt32(frame_.display_width);
  if (ret != OK) return ret;

  ret = parcel->writeInt32(frame_.display_height);
  if (ret != OK) return ret;

  ret = parcel->writeBool(frame_.removed);
  if (ret != OK) return ret;

  std::vector<ParcelableComposerLayer> layers;
  for (size_t i = 0; i < frame_.layers.size(); ++i)
    layers.push_back(ParcelableComposerLayer(frame_.layers[i]));

  ret = parcel->writeParcelableVector(layers);

  return ret;
}

status_t ParcelableComposerFrame::readFromParcel(const Parcel* parcel) {
  status_t ret = parcel->readUint64(&frame_.display_id);
  if (ret != OK) return ret;

  ret = parcel->readInt32(&frame_.display_width);
  if (ret != OK) return ret;

  ret = parcel->readInt32(&frame_.display_height);
  if (ret != OK) return ret;

  ret = parcel->readBool(&frame_.removed);
  if (ret != OK) return ret;

  std::vector<ParcelableComposerLayer> layers;
  ret = parcel->readParcelableVector(&layers);
  if (ret != OK) return ret;

  frame_.layers.clear();
  for (size_t i = 0; i < layers.size(); ++i)
    frame_.layers.push_back(layers[i].layer());

  return ret;
}

}  // namespace dvr
}  // namespace android
