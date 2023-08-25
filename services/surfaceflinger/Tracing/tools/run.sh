#!/usr/bin/env bash

set -ex

# Build, push and run layertracegenerator
$ANDROID_BUILD_TOP/build/soong/soong_ui.bash --make-mode layertracegenerator
adb wait-for-device && adb push $OUT/system/bin/layertracegenerator /data/layertracegenerator

if [ -z "$1" ]
  then
    echo "Writing transaction trace to file"
    adb shell service call SurfaceFlinger 1041 i32 0
    adb shell /data/layertracegenerator
  else
    echo "Pushing transaction trace to device"
    adb push $1 /data/transaction_trace.winscope
    adb shell /data/layertracegenerator /data/transaction_trace.winscope
fi
adb pull /data/misc/wmtrace/layers_trace.winscope