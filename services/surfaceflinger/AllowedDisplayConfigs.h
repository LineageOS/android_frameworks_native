/*
 * Copyright 2019 The Android Open Source Project
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

#include <log/log.h>
#include <vector>

/*
 * Used to represent the Display Configurations allowed to be set by SurfaceFlinger
 */
class AllowedDisplayConfigs {
private:
    // Defining ConstructorTag as private to prevent instantiating this class from outside
    // while still allowing it to be constructed by std::make_unique
    struct ConstructorTag {};

public:
    AllowedDisplayConfigs(ConstructorTag) {}

    class Builder {
    public:
        Builder()
              : mAllowedDisplayConfigs(std::make_unique<AllowedDisplayConfigs>(ConstructorTag{})) {}

        std::unique_ptr<const AllowedDisplayConfigs> build() {
            return std::move(mAllowedDisplayConfigs);
        }

        // add a config to the allowed config set
        Builder& addConfig(int32_t config) {
            mAllowedDisplayConfigs->addConfig(config);
            return *this;
        }

    private:
        std::unique_ptr<AllowedDisplayConfigs> mAllowedDisplayConfigs;
    };

    bool isConfigAllowed(int32_t config) const {
        return (std::find(mConfigs.begin(), mConfigs.end(), config) != mConfigs.end());
    }

    void getAllowedConfigs(std::vector<int32_t>* outConfigs) const {
        if (outConfigs) {
            *outConfigs = mConfigs;
        }
    }

private:
    // add a config to the allowed config set
    void addConfig(int32_t config) { mConfigs.push_back(config); }

    std::vector<int32_t> mConfigs;
};
