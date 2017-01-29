#!/bin/bash
# Build and copy libgvr from Google3. Make sure that your local Google3 client
# is up-to-date by running `p4 sync` before executing this script.
#
# Usage:
# build_gvr_prebuilts.sh --google3_dir=<path_google3_client_root>

source gbash.sh || exit

DEFINE_string --required "google3_dir" "" \
  "Path to the root directory of Google3 client"

BLAZE_COMMON_OPTS=(
  --compilation_mode=opt
  --copt=-fdata-sections
  --copt=-ffunction-sections
  --define='prod=1'
  --define='enable_experimental_sdk=1'
  --linkopt=-Wl,--gc-sections
)

function copy_file() {
  cp -v "${1}" ${CURRENT_DIR}/"${2}"
}

function copy_gvr_headers() {
  echo "Copy GVR headers ..."

  GVR_HEADER_DIR="include/vr/gvr/capi/include"
  GVR_SOURCE_DIR="include/vr/gvr/capi/src"

  # GVR public headers
  copy_file "vr/gvr/capi/include/gvr.h" ${GVR_HEADER_DIR}
  copy_file "vr/gvr/capi/include/gvr_audio.h" ${GVR_HEADER_DIR}
  copy_file "vr/gvr/capi/include/gvr_controller.h" ${GVR_HEADER_DIR}
  copy_file "vr/gvr/capi/include/gvr_types.h" ${GVR_HEADER_DIR}

  # GVR private and experimental headers
  copy_file "vr/gvr/capi/src/gvr_experimental.h" ${GVR_SOURCE_DIR}
  copy_file "vr/gvr/capi/src/gvr_private.h" ${GVR_SOURCE_DIR}
  copy_file "vr/gvr/capi/src/gvr_types_experimental.h" ${GVR_SOURCE_DIR}
}

function build_gvr_libs() {
  echo "Build GVR libraries ..."

  blaze build \
    //java/com/google/vr/sdk/release:common_library.aar \
    //vr/gvr/platform:libgvr.so \
    //vr/gvr/platform:libgvr_audio.so \
    ${BLAZE_COMMON_OPTS[@]} --config=android_arm --symlink_prefix blaze-arm-

  blaze build \
    //vr/gvr/platform:libgvr.so \
    //vr/gvr/platform:libgvr_audio.so \
    ${BLAZE_COMMON_OPTS[@]} --config=android_arm64 --symlink_prefix blaze-arm64-

    blaze build \
    //java/com/google/vr/sdk/release:common_library.aar \
    //vr/gvr/platform:libgvr.so \
    //vr/gvr/platform:libgvr_audio.so \
    ${BLAZE_COMMON_OPTS[@]} --config=android_x86 --symlink_prefix blaze-x86-

  blaze build \
    //vr/gvr/platform:libgvr.so \
    //vr/gvr/platform:libgvr_audio.so \
    ${BLAZE_COMMON_OPTS[@]} --config=android_x86_64 --symlink_prefix blaze-x86_64-

  copy_file "blaze-arm-genfiles/java/com/google/vr/sdk/release/common_library.aar" \
    "lib/common_library.aar"
  copy_file "blaze-arm-genfiles/vr/gvr/platform/libgvr.so" "lib/android_arm"
  copy_file "blaze-arm-genfiles/vr/gvr/platform/libgvr_audio.so" "lib/android_arm"
  copy_file "blaze-arm64-genfiles/vr/gvr/platform/libgvr.so" "lib/android_arm64"
  copy_file "blaze-arm64-genfiles/vr/gvr/platform/libgvr_audio.so" "lib/android_arm64"
  copy_file "blaze-x86-genfiles/vr/gvr/platform/libgvr.so" "lib/android_x86"
  copy_file "blaze-x86-genfiles/vr/gvr/platform/libgvr_audio.so" "lib/android_x86"
  copy_file "blaze-x86_64-genfiles/vr/gvr/platform/libgvr.so" "lib/android_x86_64"
  copy_file "blaze-x86_64-genfiles/vr/gvr/platform/libgvr_audio.so" "lib/android_x86_64"
}

function main() {
  set -ex

  CURRENT_DIR=$(pwd)
  GOOGLE3_DIR=${FLAGS_google3_dir}

  cd ${GOOGLE3_DIR}
  copy_gvr_headers
  build_gvr_libs
}

gbash::init_google "$@"
main "$@"
