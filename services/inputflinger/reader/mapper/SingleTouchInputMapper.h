/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef _UI_INPUTREADER_SINGLE_TOUCH_INPUT_MAPPER_H
#define _UI_INPUTREADER_SINGLE_TOUCH_INPUT_MAPPER_H

#include "SingleTouchMotionAccumulator.h"
#include "TouchInputMapper.h"

namespace android {

class SingleTouchInputMapper : public TouchInputMapper {
public:
    explicit SingleTouchInputMapper(InputDeviceContext& deviceContext);
    virtual ~SingleTouchInputMapper();

    virtual void reset(nsecs_t when) override;
    virtual void process(const RawEvent* rawEvent) override;

protected:
    virtual void syncTouch(nsecs_t when, RawState* outState);
    virtual void configureRawPointerAxes();
    virtual bool hasStylus() const;

private:
    SingleTouchMotionAccumulator mSingleTouchMotionAccumulator;
};

} // namespace android

#endif // _UI_INPUTREADER_SINGLE_TOUCH_INPUT_MAPPER_H