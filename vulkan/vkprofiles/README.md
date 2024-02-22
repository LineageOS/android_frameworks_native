
Get a local copy of the Vulkan-Profiles repository (https://github.com/KhronosGroup/Vulkan-Profiles/)

NOTE: If the Vulkan-Headers you need for generation is later than the one that exists in
`external/vulkan-headers`, then `external/vulkan-headers` will need to be updated to match.
These updates to `external/vulkan` need to be made in AOSP. Changes to `ndk_translation` may
need to be first made in internal-main.

Run Vulkan-Profiles/scripts/gen_profiles_solutions.py in debug mode.

Debug mode (at time of writing) requires a dedicated debug folder within the output-library location.
~/Vulkan-Profiles$ mkdir debug
~/Vulkan-Profiles$ python3 scripts/gen_profiles_solution.py --debug  --registry ~/<PATH_TO_YOUR_ANDROID_REPO>/external/vulkan-headers/registry/vk.xml --input ~/android/main/frameworks/native/vulkan/vkprofiles/profiles/ --output-library-inc . --output-library-src .

Take the generated vulkan_profiles.h and vulkan_profiles.cpp from the debug directory you just created.

~/Vulkan-Profiles$ cp debug/vulkan_profiles.cpp <PATH_TO_YOUR_ANDROID_REPO>/frameworks/native/vulkan/vkprofile/generated/
~/Vulkan-Profiles$ cp debug/vulkan_profiles.h <PATH_TO_YOUR_ANDROID_REPO>/frameworks/native/vulkan/vkprofile/generated/


The files need to be modified to land.
1. Replace the generated license with the correct Android license
(https://cs.android.com/android/platform/superproject/main/+/main:development/docs/copyright-templates/c.txt).
Make sure to set the copyright to the current year. You should also remove the `This file is ***GENERATED***` part.
2. Add VK_USE_PLATFORM_ANDROID_KHR between the license and the first includes for vulkan_profiles.cpp
```
 */

#ifndef VK_USE_PLATFORM_ANDROID_KHR
#define VK_USE_PLATFORM_ANDROID_KHR
#endif

#include ...
```
3. Rewrite the includes so that `vulkan_profiles.h` is correctly included
4. Modify the #define `VP_DEBUG_MESSAGE_CALLBACK(MSG) ...` from "Profiles ERROR/WARNING" to "vkprofiles ERROR/WARNING"
5. You may need to modify the Android.bp to remove warnings as errors, e.g. `"-Wno-error=unused-parameter",`
6. Add `clang-format off` to the beginning and `clang-format on` to the end of the files
