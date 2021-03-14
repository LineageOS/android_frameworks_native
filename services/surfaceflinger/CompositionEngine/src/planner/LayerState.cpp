/*
 * Copyright 2021 The Android Open Source Project
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

#include <compositionengine/impl/planner/LayerState.h>

namespace {
extern "C" const char* __attribute__((unused)) __asan_default_options() {
    return "detect_container_overflow=0";
}
} // namespace

namespace android::compositionengine::impl::planner {

LayerState::LayerState(compositionengine::OutputLayer* layer)
      : mOutputLayer(layer),
        mColorTransform({[](auto layer) {
                             const auto state = layer->getLayerFE().getCompositionState();
                             return state->colorTransformIsIdentity ? mat4{}
                                                                    : state->colorTransform;
                         },
                         [](const mat4& mat) {
                             using namespace std::string_literals;
                             std::vector<std::string> split =
                                     base::Split(std::string(mat.asString().string()), "\n"s);
                             split.pop_back(); // Strip the last (empty) line
                             return split;
                         }}) {
    update(layer);
}

Flags<LayerStateField> LayerState::update(compositionengine::OutputLayer* layer) {
    ALOGE_IF(layer != mOutputLayer, "[%s] Expected mOutputLayer to never change", __func__);

    Flags<LayerStateField> differences;

    // Update the unique fields as well, since we have to set them at least
    // once from the OutputLayer
    differences |= mId.update(layer);
    differences |= mName.update(layer);

    for (StateInterface* field : getNonUniqueFields()) {
        differences |= field->update(layer);
    }

    return differences;
}

size_t LayerState::getHash(
        Flags<LayerStateField> skipFields = static_cast<LayerStateField>(0)) const {
    size_t hash = 0;
    for (const StateInterface* field : getNonUniqueFields()) {
        android::hashCombineSingleHashed(hash, field->getHash(skipFields));
    }

    return hash;
}

Flags<LayerStateField> LayerState::getDifferingFields(
        const LayerState& other,
        Flags<LayerStateField> skipFields = static_cast<LayerStateField>(0)) const {
    Flags<LayerStateField> differences;
    auto myFields = getNonUniqueFields();
    auto otherFields = other.getNonUniqueFields();
    for (size_t i = 0; i < myFields.size(); ++i) {
        if (skipFields.test(myFields[i]->getField())) {
            continue;
        }

        differences |= myFields[i]->getFieldIfDifferent(otherFields[i]);
    }

    return differences;
}

void LayerState::dump(std::string& result) const {
    for (const StateInterface* field : getNonUniqueFields()) {
        if (auto viewOpt = flag_name(field->getField()); viewOpt) {
            base::StringAppendF(&result, "  %16s: ", std::string(*viewOpt).c_str());
        } else {
            result.append("<UNKNOWN FIELD>:\n");
        }

        bool first = true;
        for (const std::string& line : field->toStrings()) {
            base::StringAppendF(&result, "%s%s\n", first ? "" : "                    ",
                                line.c_str());
            first = false;
        }
    }
    result.append("\n");
}

std::optional<std::string> LayerState::compare(const LayerState& other) const {
    std::string result;

    const auto& thisFields = getNonUniqueFields();
    const auto& otherFields = other.getNonUniqueFields();
    for (size_t f = 0; f < thisFields.size(); ++f) {
        const auto& thisField = thisFields[f];
        const auto& otherField = otherFields[f];
        // Skip comparing buffers
        if (thisField->getField() == LayerStateField::Buffer) {
            continue;
        }

        if (thisField->equals(otherField)) {
            continue;
        }

        if (auto viewOpt = flag_name(thisField->getField()); viewOpt) {
            base::StringAppendF(&result, "  %16s: ", std::string(*viewOpt).c_str());
        } else {
            result.append("<UNKNOWN FIELD>:\n");
        }

        const auto& thisStrings = thisField->toStrings();
        const auto& otherStrings = otherField->toStrings();
        bool first = true;
        for (size_t line = 0; line < std::max(thisStrings.size(), otherStrings.size()); ++line) {
            if (!first) {
                result.append("                    ");
            }
            first = false;

            if (line < thisStrings.size()) {
                base::StringAppendF(&result, "%-48.48s", thisStrings[line].c_str());
            } else {
                result.append("                                                ");
            }

            if (line < otherStrings.size()) {
                base::StringAppendF(&result, "%-48.48s", otherStrings[line].c_str());
            } else {
                result.append("                                                ");
            }
            result.append("\n");
        }
    }

    return result.empty() ? std::nullopt : std::make_optional(result);
}

bool operator==(const LayerState& lhs, const LayerState& rhs) {
    return lhs.mId == rhs.mId && lhs.mName == rhs.mName && lhs.mDisplayFrame == rhs.mDisplayFrame &&
            lhs.mSourceCrop == rhs.mSourceCrop && lhs.mZOrder == rhs.mZOrder &&
            lhs.mBufferTransform == rhs.mBufferTransform && lhs.mBlendMode == rhs.mBlendMode &&
            lhs.mAlpha == rhs.mAlpha && lhs.mVisibleRegion == rhs.mVisibleRegion &&
            lhs.mDataspace == rhs.mDataspace && lhs.mColorTransform == rhs.mColorTransform &&
            lhs.mCompositionType == rhs.mCompositionType &&
            lhs.mSidebandStream == rhs.mSidebandStream && lhs.mBuffer == rhs.mBuffer &&
            (lhs.mCompositionType.get() != hal::Composition::SOLID_COLOR ||
             lhs.mSolidColor == rhs.mSolidColor);
}

NonBufferHash getNonBufferHash(const std::vector<const LayerState*>& layers) {
    size_t hash = 0;
    for (const auto layer : layers) {
        android::hashCombineSingleHashed(hash, layer->getHash(LayerStateField::Buffer));
    }

    return hash;
}

} // namespace android::compositionengine::impl::planner
