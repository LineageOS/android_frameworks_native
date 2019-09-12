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

class CommandOn : public Command {
    std::string getDescription() const override { return "Turn on vibrator."; }

    std::string getUsageSummary() const override { return "<duration>"; }

    UsageDetails getUsageDetails() const override {
        UsageDetails details{
                {"<duration>", {"In milliseconds."}},
        };
        return details;
    }

    Status doArgs(Args &args) override {
        if (auto duration = args.pop<decltype(mDuration)>()) {
            mDuration = *duration;
        } else {
            std::cerr << "Missing or Invalid Duration!" << std::endl;
            return USAGE;
        }
        if (!args.empty()) {
            std::cerr << "Unexpected Arguments!" << std::endl;
            return USAGE;
        }
        return OK;
    }

    Status doMain(Args && /*args*/) override {
        auto ret = halCall(&V1_0::IVibrator::on, mDuration);

        if (!ret.isOk()) {
            return UNAVAILABLE;
        }

        std::cout << "Status: " << toString(ret) << std::endl;

        return ret == V1_0::Status::OK ? OK : ERROR;
    }

    uint32_t mDuration;
};

static const auto Command = CommandRegistry<CommandVibrator>::Register<CommandOn>("on");

} // namespace vibrator
} // namespace idlcli
} // namespace android
