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

class CommandSetExternalControl : public Command {
    std::string getDescription() const override {
        return "Enable/disable vibration external control.";
    }

    std::string getUsageSummary() const override { return "<enable>"; }

    UsageDetails getUsageDetails() const override {
        UsageDetails details{
                {"<enable>", {"0/1."}},
        };
        return details;
    }

    Status doArgs(Args &args) override {
        if (auto enable = args.pop<decltype(mEnable)>()) {
            mEnable = *enable;
        } else {
            std::cerr << "Missing Enable!" << std::endl;
            return USAGE;
        }
        return OK;
    }

    Status doMain(Args && /*args*/) override {
        auto ret = halCall(&V1_3::IVibrator::setExternalControl, mEnable);

        if (!ret.isOk()) {
            return UNAVAILABLE;
        }

        std::cout << "Status: " << toString(ret) << std::endl;

        return ret == V1_0::Status::OK ? OK : ERROR;
    }

    bool mEnable;
};

static const auto Command =
        CommandRegistry<CommandVibrator>::Register<CommandSetExternalControl>("setExternalControl");

} // namespace vibrator
} // namespace idlcli
} // namespace android
