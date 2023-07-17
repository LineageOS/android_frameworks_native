#!/bin/bash
# Copyright (C) 2023 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

color_success=$'\E'"[0;32m"
color_failed=$'\E'"[0;31m"
color_reset=$'\E'"[00m"

FUZZER_NAME=test_service_fuzzer_should_crash
FUZZER_OUT=fuzzer-output

if [ ! -f "$FUZZER_NAME" ]
then
    echo -e "${color_failed}Binary $FUZZER_NAME does not exist"
    echo "${color_reset}"
    exit 1
fi

for CRASH_TYPE in PLAIN KNOWN_UID AID_SYSTEM AID_ROOT BINDER; do
    echo "INFO: Running fuzzer : test_service_fuzzer_should_crash $CRASH_TYPE"

    ./test_service_fuzzer_should_crash "$CRASH_TYPE" -max_total_time=30 &>"$FUZZER_OUT"

    echo "INFO: Searching fuzzer output for expected crashes"
    if grep -q "Expected crash, $CRASH_TYPE." "$FUZZER_OUT"
    then
        echo -e "${color_success}Success: Found expected crash. fuzzService test successful!"
    else
        echo -e "${color_failed}Failed: Unable to find successful fuzzing output from test_service_fuzzer_should_crash"
        echo "${color_reset}"
        exit 1
    fi
done
