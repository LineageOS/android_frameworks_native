/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>

#include <android-base/mapped_file.h>
#include <input/RingBuffer.h>

#include <tensorflow/lite/core/api/error_reporter.h>
#include <tensorflow/lite/interpreter.h>
#include <tensorflow/lite/model.h>
#include <tensorflow/lite/signature_runner.h>

namespace android {

struct TfLiteMotionPredictorSample {
    // The untransformed AMOTION_EVENT_AXIS_X and AMOTION_EVENT_AXIS_Y of the sample.
    struct Point {
        float x;
        float y;
    } position;
    // The AMOTION_EVENT_AXIS_PRESSURE, _TILT, and _ORIENTATION.
    float pressure;
    float tilt;
    float orientation;
};

inline TfLiteMotionPredictorSample::Point operator-(const TfLiteMotionPredictorSample::Point& lhs,
                                                    const TfLiteMotionPredictorSample::Point& rhs) {
    return {.x = lhs.x - rhs.x, .y = lhs.y - rhs.y};
}

class TfLiteMotionPredictorModel;

// Buffer storage for a TfLiteMotionPredictorModel.
class TfLiteMotionPredictorBuffers {
public:
    // Creates buffer storage for a model with the given input length.
    TfLiteMotionPredictorBuffers(size_t inputLength);

    // Adds a motion sample to the buffers.
    void pushSample(int64_t timestamp, TfLiteMotionPredictorSample sample);

    // Returns true if the buffers are complete enough to generate a prediction.
    bool isReady() const {
        // Predictions can't be applied unless there are at least two points to determine
        // the direction to apply them in.
        return mAxisFrom && mAxisTo;
    }

    // Resets all buffers to their initial state.
    void reset();

    // Copies the buffers to those of a model for prediction.
    void copyTo(TfLiteMotionPredictorModel& model) const;

    // Returns the current axis of the buffer's samples. Only valid if isReady().
    TfLiteMotionPredictorSample axisFrom() const { return *mAxisFrom; }
    TfLiteMotionPredictorSample axisTo() const { return *mAxisTo; }

    // Returns the timestamp of the last sample.
    int64_t lastTimestamp() const { return mTimestamp; }

private:
    int64_t mTimestamp = 0;

    RingBuffer<float> mInputR;
    RingBuffer<float> mInputPhi;
    RingBuffer<float> mInputPressure;
    RingBuffer<float> mInputTilt;
    RingBuffer<float> mInputOrientation;

    // The samples defining the current polar axis.
    std::optional<TfLiteMotionPredictorSample> mAxisFrom;
    std::optional<TfLiteMotionPredictorSample> mAxisTo;
};

// A TFLite model for generating motion predictions.
class TfLiteMotionPredictorModel {
public:
    // Creates a model from an encoded Flatbuffer model.
    static std::unique_ptr<TfLiteMotionPredictorModel> create();

    ~TfLiteMotionPredictorModel();

    // Returns the length of the model's input buffers.
    size_t inputLength() const;

    // Returns the length of the model's output buffers.
    size_t outputLength() const;

    // Executes the model.
    // Returns true if the model successfully executed and the output tensors can be read.
    bool invoke();

    // Returns mutable buffers to the input tensors of inputLength() elements.
    std::span<float> inputR();
    std::span<float> inputPhi();
    std::span<float> inputPressure();
    std::span<float> inputOrientation();
    std::span<float> inputTilt();

    // Returns immutable buffers to the output tensors of identical length. Only valid after a
    // successful call to invoke().
    std::span<const float> outputR() const;
    std::span<const float> outputPhi() const;
    std::span<const float> outputPressure() const;

private:
    explicit TfLiteMotionPredictorModel(std::unique_ptr<android::base::MappedFile> model);

    void allocateTensors();
    void attachInputTensors();
    void attachOutputTensors();

    TfLiteTensor* mInputR = nullptr;
    TfLiteTensor* mInputPhi = nullptr;
    TfLiteTensor* mInputPressure = nullptr;
    TfLiteTensor* mInputTilt = nullptr;
    TfLiteTensor* mInputOrientation = nullptr;

    const TfLiteTensor* mOutputR = nullptr;
    const TfLiteTensor* mOutputPhi = nullptr;
    const TfLiteTensor* mOutputPressure = nullptr;

    std::unique_ptr<android::base::MappedFile> mFlatBuffer;
    std::unique_ptr<tflite::ErrorReporter> mErrorReporter;
    std::unique_ptr<tflite::FlatBufferModel> mModel;
    std::unique_ptr<tflite::Interpreter> mInterpreter;
    tflite::SignatureRunner* mRunner = nullptr;
};

} // namespace android
