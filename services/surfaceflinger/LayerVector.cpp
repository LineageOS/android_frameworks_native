/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "LayerVector.h"
#include "Layer.h"

namespace android {
LayerVector::LayerVector(const LayerVector& rhs) : SortedVector<sp<Layer>>(rhs) {
}

int LayerVector::do_compare(const void* lhs, const void* rhs) const
{
    // sort layers per layer-stack, then by z-order and finally by sequence
    const auto& l = *reinterpret_cast<const sp<Layer>*>(lhs);
    const auto& r = *reinterpret_cast<const sp<Layer>*>(rhs);

    uint32_t ls = l->getCurrentState().layerStack;
    uint32_t rs = r->getCurrentState().layerStack;
    if (ls != rs)
        return ls - rs;

    uint32_t lz = l->getCurrentState().z;
    uint32_t rz = r->getCurrentState().z;
    if (lz != rz)
        return lz - rz;

    return l->sequence - r->sequence;
}

void LayerVector::traverseInZOrder(const std::function<void(Layer*)>& consume) const {
    for (size_t i = 0; i < size(); i++) {
        const auto& layer = (*this)[i];
        if (layer->getDrawingState().zOrderRelativeOf != nullptr) {
            continue;
        }
        layer->traverseInZOrder(consume);
    }
}

void LayerVector::traverseInReverseZOrder(const std::function<void(Layer*)>& consume) const {
    for (auto i = static_cast<int64_t>(size()) - 1; i >= 0; i--) {
        const auto& layer = (*this)[i];
        if (layer->getDrawingState().zOrderRelativeOf != nullptr) {
            continue;
        }
        layer->traverseInReverseZOrder(consume);
     }
}
} // namespace android
