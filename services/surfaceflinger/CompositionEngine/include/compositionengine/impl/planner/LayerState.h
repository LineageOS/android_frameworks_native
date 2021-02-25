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

#pragma once

#include <android-base/strings.h>
#include <compositionengine/LayerFE.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/OutputLayer.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>
#include <input/Flags.h>

#include <string>

#include "DisplayHardware/Hal.h"

namespace std {
template <typename T>
struct hash<android::sp<T>> {
    size_t operator()(const android::sp<T>& p) { return std::hash<void*>()(p.get()); }
};
} // namespace std

namespace android::compositionengine::impl::planner {

using LayerId = int32_t;

// clang-format off
enum class LayerStateField : uint32_t {
    Id              = 1u << 0,
    Name            = 1u << 1,
    DisplayFrame    = 1u << 2,
    SourceCrop      = 1u << 3,
    ZOrder          = 1u << 4,
    BufferTransform = 1u << 5,
    BlendMode       = 1u << 6,
    Alpha           = 1u << 7,
    VisibleRegion   = 1u << 8,
    Dataspace       = 1u << 9,
    ColorTransform  = 1u << 10,
    CompositionType = 1u << 11,
    SidebandStream  = 1u << 12,
    Buffer          = 1u << 13,
    SolidColor      = 1u << 14,
};
// clang-format on

std::string to_string(LayerStateField field);

// An abstract interface allows us to iterate over all of the OutputLayerState fields
// without having to worry about their templated types.
// See `LayerState::getNonUniqueFields` below.
class StateInterface {
public:
    virtual ~StateInterface() = default;

    virtual Flags<LayerStateField> update(const compositionengine::OutputLayer* layer) = 0;

    virtual size_t getHash(Flags<LayerStateField> skipFields) const = 0;

    virtual LayerStateField getField() const = 0;

    virtual Flags<LayerStateField> getFieldIfDifferent(const StateInterface* other) const = 0;

    virtual bool equals(const StateInterface* other) const = 0;

    virtual std::vector<std::string> toStrings() const = 0;
};

template <typename T, LayerStateField FIELD>
class OutputLayerState : public StateInterface {
public:
    using ReadFromLayerState = std::function<T(const compositionengine::OutputLayer* layer)>;
    using ToStrings = std::function<std::vector<std::string>(const T&)>;
    using Equals = std::function<bool(const T&, const T&)>;

    static ToStrings getDefaultToStrings() {
        return [](const T& value) {
            using std::to_string;
            return std::vector<std::string>{to_string(value)};
        };
    }

    static ToStrings getHalToStrings() {
        return [](const T& value) { return std::vector<std::string>{toString(value)}; };
    }

    static Equals getDefaultEquals() {
        return [](const T& lhs, const T& rhs) { return lhs == rhs; };
    }

    OutputLayerState(ReadFromLayerState reader,
                     ToStrings toStrings = OutputLayerState::getDefaultToStrings(),
                     Equals equals = OutputLayerState::getDefaultEquals())
          : mReader(reader), mToStrings(toStrings), mEquals(equals) {}

    ~OutputLayerState() override = default;

    // Returns this member's field flag if it was changed
    Flags<LayerStateField> update(const compositionengine::OutputLayer* layer) override {
        T newValue = mReader(layer);
        if (!mEquals(mValue, newValue)) {
            mValue = newValue;
            mHash = {};
            return FIELD;
        }
        return {};
    }

    LayerStateField getField() const override { return FIELD; }
    const T& get() const { return mValue; }

    size_t getHash(Flags<LayerStateField> skipFields) const override {
        if (skipFields.test(FIELD)) {
            return 0;
        }
        if (!mHash) {
            mHash = std::hash<T>{}(mValue);
        }
        return *mHash;
    }

    Flags<LayerStateField> getFieldIfDifferent(const StateInterface* other) const override {
        if (other->getField() != FIELD) {
            return {};
        }

        // The early return ensures that this downcast is sound
        const OutputLayerState* otherState = static_cast<const OutputLayerState*>(other);
        return *this != *otherState ? FIELD : Flags<LayerStateField>{};
    }

    bool equals(const StateInterface* other) const override {
        if (other->getField() != FIELD) {
            return false;
        }

        // The early return ensures that this downcast is sound
        const OutputLayerState* otherState = static_cast<const OutputLayerState*>(other);
        return *this == *otherState;
    }

    std::vector<std::string> toStrings() const override { return mToStrings(mValue); }

    bool operator==(const OutputLayerState& other) const { return mEquals(mValue, other.mValue); }
    bool operator!=(const OutputLayerState& other) const { return !(*this == other); }

private:
    const ReadFromLayerState mReader;
    const ToStrings mToStrings;
    const Equals mEquals;
    T mValue = {};
    mutable std::optional<size_t> mHash = {};
};

class LayerState {
public:
    LayerState(compositionengine::OutputLayer* layer);

    // Returns which fields were updated
    Flags<LayerStateField> update(compositionengine::OutputLayer*);

    size_t getHash(Flags<LayerStateField> skipFields) const;

    Flags<LayerStateField> getDifferingFields(const LayerState& other,
                                              Flags<LayerStateField> skipFields) const;

    compositionengine::OutputLayer* getOutputLayer() const { return mOutputLayer; }
    int32_t getId() const { return mId.get(); }
    const std::string& getName() const { return mName.get(); }
    Rect getDisplayFrame() const { return mDisplayFrame.get(); }
    hardware::graphics::composer::hal::Composition getCompositionType() const {
        return mCompositionType.get();
    }
    const sp<GraphicBuffer>& getBuffer() const { return mBuffer.get(); }

    void incrementFramesSinceBufferUpdate() { ++mFramesSinceBufferUpdate; }
    void resetFramesSinceBufferUpdate() { mFramesSinceBufferUpdate = 0; }
    int64_t getFramesSinceBufferUpdate() const { return mFramesSinceBufferUpdate; }

    void dump(std::string& result) const;
    std::optional<std::string> compare(const LayerState& other) const;

    // This makes LayerState's private members accessible to the operator
    friend bool operator==(const LayerState& lhs, const LayerState& rhs);
    friend bool operator!=(const LayerState& lhs, const LayerState& rhs) { return !(lhs == rhs); }

private:
    compositionengine::OutputLayer* mOutputLayer = nullptr;

    OutputLayerState<LayerId, LayerStateField::Id> mId{
            [](const compositionengine::OutputLayer* layer) {
                return layer->getLayerFE().getSequence();
            }};

    OutputLayerState<std::string, LayerStateField::Name>
            mName{[](auto layer) { return layer->getLayerFE().getDebugName(); },
                  [](const std::string& name) { return std::vector<std::string>{name}; }};

    // Output-dependent geometry state

    OutputLayerState<Rect, LayerStateField::DisplayFrame>
            mDisplayFrame{[](auto layer) { return layer->getState().displayFrame; },
                          [](const Rect& rect) {
                              return std::vector<std::string>{
                                      base::StringPrintf("[%d, %d, %d, %d]", rect.left, rect.top,
                                                         rect.right, rect.bottom)};
                          }};

    OutputLayerState<FloatRect, LayerStateField::SourceCrop>
            mSourceCrop{[](auto layer) { return layer->getState().sourceCrop; },
                        [](const FloatRect& rect) {
                            return std::vector<std::string>{
                                    base::StringPrintf("[%.2f, %.2f, %.2f, %.2f]", rect.left,
                                                       rect.top, rect.right, rect.bottom)};
                        }};

    OutputLayerState<uint32_t, LayerStateField::ZOrder> mZOrder{
            [](auto layer) { return layer->getState().z; }};

    using BufferTransformState = OutputLayerState<hardware::graphics::composer::hal::Transform,
                                                  LayerStateField::BufferTransform>;
    BufferTransformState mBufferTransform{[](auto layer) {
                                              return layer->getState().bufferTransform;
                                          },
                                          BufferTransformState::getHalToStrings()};

    // Output-independent geometry state

    using BlendModeState = OutputLayerState<hardware::graphics::composer::hal::BlendMode,
                                            LayerStateField::BlendMode>;
    BlendModeState mBlendMode{[](auto layer) {
                                  return layer->getLayerFE().getCompositionState()->blendMode;
                              },
                              BlendModeState::getHalToStrings()};

    OutputLayerState<float, LayerStateField::Alpha> mAlpha{
            [](auto layer) { return layer->getLayerFE().getCompositionState()->alpha; }};

    // TODO(b/180638831): Generic layer metadata

    // Output-dependent per-frame state

    OutputLayerState<Region, LayerStateField::VisibleRegion>
            mVisibleRegion{[](auto layer) { return layer->getState().visibleRegion; },
                           [](const Region& region) {
                               using namespace std::string_literals;
                               std::string dump;
                               region.dump(dump, "");
                               std::vector<std::string> split = base::Split(dump, "\n"s);
                               split.erase(split.begin()); // Strip the header
                               split.pop_back();           // Strip the last (empty) line
                               for (std::string& line : split) {
                                   line.erase(0, 4); // Strip leading padding before each rect
                               }
                               return split;
                           },
                           [](const Region& lhs, const Region& rhs) {
                               return lhs.hasSameRects(rhs);
                           }};

    using DataspaceState = OutputLayerState<ui::Dataspace, LayerStateField::Dataspace>;
    DataspaceState mDataspace{[](auto layer) { return layer->getState().dataspace; },
                              DataspaceState::getHalToStrings()};

    // TODO(b/180638831): Buffer format

    // Output-independent per-frame state

    OutputLayerState<mat4, LayerStateField::ColorTransform>
            mColorTransform{[](auto layer) {
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
                            }};

    // TODO(b/180638831): Surface damage

    using CompositionTypeState = OutputLayerState<hardware::graphics::composer::hal::Composition,
                                                  LayerStateField::CompositionType>;
    CompositionTypeState
            mCompositionType{[](auto layer) {
                                 return layer->getState().forceClientComposition
                                         ? hardware::graphics::composer::hal::Composition::CLIENT
                                         : layer->getLayerFE()
                                                   .getCompositionState()
                                                   ->compositionType;
                             },
                             CompositionTypeState::getHalToStrings()};

    OutputLayerState<void*, LayerStateField::SidebandStream>
            mSidebandStream{[](auto layer) {
                                return layer->getLayerFE()
                                        .getCompositionState()
                                        ->sidebandStream.get();
                            },
                            [](void* p) {
                                return std::vector<std::string>{base::StringPrintf("%p", p)};
                            }};

    OutputLayerState<sp<GraphicBuffer>, LayerStateField::Buffer>
            mBuffer{[](auto layer) { return layer->getLayerFE().getCompositionState()->buffer; },
                    [](const sp<GraphicBuffer>& buffer) {
                        return std::vector<std::string>{base::StringPrintf("%p", buffer.get())};
                    }};

    int64_t mFramesSinceBufferUpdate = 0;

    OutputLayerState<half4, LayerStateField::SolidColor>
            mSolidColor{[](auto layer) { return layer->getLayerFE().getCompositionState()->color; },
                        [](const half4& vec) {
                            std::stringstream stream;
                            stream << vec;
                            return std::vector<std::string>{stream.str()};
                        }};

    std::array<StateInterface*, 13> getNonUniqueFields() {
        std::array<const StateInterface*, 13> constFields =
                const_cast<const LayerState*>(this)->getNonUniqueFields();
        std::array<StateInterface*, 13> fields;
        std::transform(constFields.cbegin(), constFields.cend(), fields.begin(),
                       [](const StateInterface* constField) {
                           return const_cast<StateInterface*>(constField);
                       });
        return fields;
    }

    std::array<const StateInterface*, 13> getNonUniqueFields() const {
        return {
                &mDisplayFrame,   &mSourceCrop,      &mZOrder,         &mBufferTransform,
                &mBlendMode,      &mAlpha,           &mVisibleRegion,  &mDataspace,
                &mColorTransform, &mCompositionType, &mSidebandStream, &mBuffer,
                &mSolidColor,
        };
    }
};

using NonBufferHash = size_t;
NonBufferHash getNonBufferHash(const std::vector<const LayerState*>&);

} // namespace android::compositionengine::impl::planner
