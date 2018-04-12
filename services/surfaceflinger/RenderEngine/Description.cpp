/*
 * Copyright 2013 The Android Open Source Project
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

#include <stdint.h>
#include <string.h>

#include <utils/TypeHelpers.h>

#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>

#include "Description.h"

namespace android {

void Description::setPremultipliedAlpha(bool premultipliedAlpha) {
    mPremultipliedAlpha = premultipliedAlpha;
}

void Description::setOpaque(bool opaque) {
    mOpaque = opaque;
}

void Description::setTexture(const Texture& texture) {
    mTexture = texture;
    mTextureEnabled = true;
}

void Description::disableTexture() {
    mTextureEnabled = false;
}

void Description::setColor(const half4& color) {
    mColor = color;
}

void Description::setProjectionMatrix(const mat4& mtx) {
    mProjectionMatrix = mtx;
}

void Description::setColorMatrix(const mat4& mtx) {
    const mat4 identity;
    mColorMatrix = mtx;
    mColorMatrixEnabled = (mtx != identity);
}

const mat4& Description::getColorMatrix() const {
    return mColorMatrix;
}

void Description::setY410BT2020(bool enable) {
    mY410BT2020 = enable;
}

void Description::setInputTransferFunction(TransferFunction transferFunction) {
    mInputTransferFunction = transferFunction;
}

void Description::setOutputTransferFunction(TransferFunction transferFunction) {
    mOutputTransferFunction = transferFunction;
}

} /* namespace android */
