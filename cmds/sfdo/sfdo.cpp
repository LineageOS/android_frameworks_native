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
#include <inttypes.h>
#include <stdint.h>
#include <any>
#include <map>

#include <cutils/properties.h>
#include <sys/resource.h>
#include <utils/Log.h>

#include <gui/ISurfaceComposer.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/SurfaceControl.h>
#include <private/gui/ComposerServiceAIDL.h>

using namespace android;

std::map<std::string, std::any> g_functions;

enum class ParseToggleResult {
    kError,
    kFalse,
    kTrue,
};

const std::map<std::string, std::string> g_function_details = {
        {"debugFlash", "[optional(delay)] Perform a debug flash."},
        {"frameRateIndicator", "[hide | show] displays the framerate in the top left corner."},
        {"scheduleComposite", "Force composite ahead of next VSYNC."},
        {"scheduleCommit", "Force commit ahead of next VSYNC."},
        {"scheduleComposite", "PENDING - if you have a good understanding let me know!"},
        {"forceClientComposition",
         "[enabled | disabled] When enabled, it disables "
         "Hardware Overlays, and routes all window composition to the GPU. This can "
         "help check if there is a bug in HW Composer."},
};

static void ShowUsage() {
    std::cout << "usage: sfdo [help, frameRateIndicator show, debugFlash enabled, ...]\n\n";
    for (const auto& sf : g_functions) {
        const std::string fn = sf.first;
        std::string fdetails = "TODO";
        if (g_function_details.find(fn) != g_function_details.end())
            fdetails = g_function_details.find(fn)->second;
        std::cout << "    " << fn << ": " << fdetails << "\n";
    }
}

// Returns 1 for positive keywords and 0 for negative keywords.
// If the string does not match any it will return -1.
ParseToggleResult parseToggle(const char* str) {
    const std::unordered_set<std::string> positive{"1",  "true",    "y",   "yes",
                                                   "on", "enabled", "show"};
    const std::unordered_set<std::string> negative{"0",   "false",    "n",   "no",
                                                   "off", "disabled", "hide"};

    const std::string word(str);
    if (positive.count(word)) {
        return ParseToggleResult::kTrue;
    }
    if (negative.count(word)) {
        return ParseToggleResult::kFalse;
    }

    return ParseToggleResult::kError;
}

int frameRateIndicator(int argc, char** argv) {
    bool hide = false, show = false;
    if (argc == 3) {
        show = strcmp(argv[2], "show") == 0;
        hide = strcmp(argv[2], "hide") == 0;
    }

    if (show || hide) {
        ComposerServiceAIDL::getComposerService()->enableRefreshRateOverlay(show);
    } else {
        std::cerr << "Incorrect usage of frameRateIndicator. Missing [hide | show].\n";
        return -1;
    }
    return 0;
}

int debugFlash(int argc, char** argv) {
    int delay = 0;
    if (argc == 3) {
        delay = atoi(argv[2]) == 0;
    }

    ComposerServiceAIDL::getComposerService()->setDebugFlash(delay);
    return 0;
}

int scheduleComposite([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {
    ComposerServiceAIDL::getComposerService()->scheduleComposite();
    return 0;
}

int scheduleCommit([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {
    ComposerServiceAIDL::getComposerService()->scheduleCommit();
    return 0;
}

int forceClientComposition(int argc, char** argv) {
    bool enabled = true;
    // A valid command looks like this:
    // adb shell sfdo forceClientComposition enabled
    if (argc >= 3) {
        const ParseToggleResult toggle = parseToggle(argv[2]);
        if (toggle == ParseToggleResult::kError) {
            std::cerr << "Incorrect usage of forceClientComposition. "
                         "Missing [enabled | disabled].\n";
            return -1;
        }
        if (argc > 3) {
            std::cerr << "Too many arguments after [enabled | disabled]. "
                         "Ignoring extra arguments.\n";
        }
        enabled = (toggle == ParseToggleResult::kTrue);
    } else {
        std::cerr << "Incorrect usage of forceClientComposition. Missing [enabled | disabled].\n";
        return -1;
    }

    ComposerServiceAIDL::getComposerService()->forceClientComposition(enabled);
    return 0;
}

int main(int argc, char** argv) {
    std::cout << "Execute SurfaceFlinger internal commands.\n";
    std::cout << "sfdo requires to be run with root permissions..\n";

    g_functions["frameRateIndicator"] = frameRateIndicator;
    g_functions["debugFlash"] = debugFlash;
    g_functions["scheduleComposite"] = scheduleComposite;
    g_functions["scheduleCommit"] = scheduleCommit;
    g_functions["forceClientComposition"] = forceClientComposition;

    if (argc > 1 && g_functions.find(argv[1]) != g_functions.end()) {
        std::cout << "Running: " << argv[1] << "\n";
        const std::string key(argv[1]);
        const auto fn = g_functions[key];
        int result = std::any_cast<int (*)(int, char**)>(fn)(argc, argv);
        if (result == 0) {
            std::cout << "Success.\n";
        }
        return result;
    } else {
        ShowUsage();
    }
    return 0;
}