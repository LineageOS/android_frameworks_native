#
# Copyright 2019 The Android Open Source Project
# Copyright 2019 The halogenOS Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Provides overrides to configure the Dalvik heap for a 16 GiB phone

PRODUCT_PROPERTY_OVERRIDES += \
    dalvik.vm.heapstartsize=32m \
    dalvik.vm.heapgrowthlimit=448m \
    dalvik.vm.heapsize=640m \
    dalvik.vm.heaptargetutilization=0.4 \
    dalvik.vm.heapminfree=16m \
    dalvik.vm.heapmaxfree=64m
