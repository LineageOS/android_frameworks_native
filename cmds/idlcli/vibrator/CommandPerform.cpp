/*
 * Copyright (C) 2019 The Android Open Source Project *
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

#include "utils.h"
#include "vibrator.h"

namespace android {
namespace idlcli {

class CommandVibrator;

namespace vibrator {

using V1_0::EffectStrength;
using V1_3::Effect;

class CommandPerform : public Command {
    std::string getDescription() const override { return "Perform vibration effect."; }

    std::string getUsageSummary() const override { return "<effect> <strength>"; }

    UsageDetails getUsageDetails() const override {
        UsageDetails details{
                {"<effect>", {"Effect ID."}},
                {"<strength>", {"0-2."}},
        };
        return details;
    }

    Status doArgs(Args &args) override {
        if (auto effect = args.pop<decltype(mEffect)>()) {
            mEffect = *effect;
            std::cout << "Effect: " << toString(mEffect) << std::endl;
        } else {
            std::cerr << "Missing or Invalid Effect!" << std::endl;
            return USAGE;
        }
        if (auto strength = args.pop<decltype(mStrength)>()) {
            mStrength = *strength;
            std::cout << "Strength: " << toString(mStrength) << std::endl;
        } else {
            std::cerr << "Missing or Invalid Strength!" << std::endl;
            return USAGE;
        }
        if (!args.empty()) {
            std::cerr << "Unexpected Arguments!" << std::endl;
            return USAGE;
        }
        return OK;
    }

    Status doMain(Args && /*args*/) override {
        Return<void> ret;
        V1_0::Status status;
        uint32_t lengthMs;
        auto callback = [&status, &lengthMs](V1_0::Status retStatus, uint32_t retLengthMs) {
            status = retStatus;
            lengthMs = retLengthMs;
        };

        if (auto hal = getHal<V1_3::IVibrator>()) {
            ret = hal->call(&V1_3::IVibrator::perform_1_3, static_cast<V1_3::Effect>(mEffect),
                            mStrength, callback);
        } else if (auto hal = getHal<V1_2::IVibrator>()) {
            ret = hal->call(&V1_2::IVibrator::perform_1_2, static_cast<V1_2::Effect>(mEffect),
                            mStrength, callback);
        } else if (auto hal = getHal<V1_1::IVibrator>()) {
            ret = hal->call(&V1_1::IVibrator::perform_1_1, static_cast<V1_1::Effect_1_1>(mEffect),
                            mStrength, callback);
        } else if (auto hal = getHal<V1_0::IVibrator>()) {
            ret = hal->call(&V1_0::IVibrator::perform, static_cast<V1_0::Effect>(mEffect),
                            mStrength, callback);
        } else {
            ret = NullptrStatus<void>();
        }

        if (!ret.isOk()) {
            return UNAVAILABLE;
        }

        std::cout << "Status: " << toString(status) << std::endl;
        std::cout << "Length: " << lengthMs << std::endl;

        return status == V1_0::Status::OK ? OK : ERROR;
    }

    Effect mEffect;
    EffectStrength mStrength;
};

static const auto Command = CommandRegistry<CommandVibrator>::Register<CommandPerform>("perform");

} // namespace vibrator
} // namespace idlcli
} // namespace android
