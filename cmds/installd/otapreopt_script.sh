#!/system/bin/sh

#
# Copyright (C) 2016 The Android Open Source Project
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

# This script runs as a postinstall step to drive otapreopt. It comes with the
# OTA package, but runs /system/bin/otapreopt_chroot in the (old) active system
# image. See system/extras/postinst/postinst.sh for some docs.

TARGET_SLOT="$1"
STATUS_FD="$2"

# Maximum number of packages/steps.
MAXIMUM_PACKAGES=1000

# First ensure the system is booted. This is to work around issues when cmd would
# infinitely loop trying to get a service manager (which will never come up in that
# mode). b/30797145
BOOT_PROPERTY_NAME="dev.bootcomplete"

BOOT_COMPLETE=$(getprop $BOOT_PROPERTY_NAME)
if [ "$BOOT_COMPLETE" != "1" ] ; then
  echo "$0: Error: boot-complete not detected."
  # We must return 0 to not block sideload.
  exit 0
fi

# Compute target slot suffix.
# TODO: Once bootctl is not restricted, we should query from there. Or get this from
#       update_engine as a parameter.
if [ "$TARGET_SLOT" = "0" ] ; then
  TARGET_SLOT_SUFFIX="_a"
elif [ "$TARGET_SLOT" = "1" ] ; then
  TARGET_SLOT_SUFFIX="_b"
else
  echo "$0: Unknown target slot $TARGET_SLOT"
  exit 1
fi

if pm art on-ota-staged --slot "$TARGET_SLOT_SUFFIX"; then
  # Handled by Pre-reboot Dexopt.
  exit 0
fi
echo "Pre-reboot Dexopt not enabled. Fall back to otapreopt."

if [ "$(/system/bin/otapreopt_chroot --version)" != 2 ]; then
  # We require an updated chroot wrapper that reads dexopt commands from stdin.
  # Even if we kept compat with the old binary, the OTA preopt wouldn't work due
  # to missing sepolicy rules, so there's no use spending time trying to dexopt
  # (b/291974157).
  echo "$0: Current system image is too old to work with OTA preopt - skipping."
  exit 0
fi

PREPARE=$(cmd otadexopt prepare)
# Note: Ignore preparation failures. Step and done will fail and exit this.
#       This is necessary to support suspends - the OTA service will keep
#       the state around for us.

# Create an array with all dexopt commands in advance, to know how many there are.
otadexopt_cmds=()
while (( ${#otadexopt_cmds[@]} < MAXIMUM_PACKAGES )) ; do
  DONE=$(cmd otadexopt done)
  if [ "$DONE" = "OTA complete." ] ; then
    break
  fi
  otadexopt_cmds+=("$(cmd otadexopt next)")
done

DONE=$(cmd otadexopt done)
cmd otadexopt cleanup

echo "$0: Using streaming otapreopt_chroot on ${#otadexopt_cmds[@]} packages"

function print_otadexopt_cmds {
  for cmd in "${otadexopt_cmds[@]}" ; do
    print "$cmd"
  done
}

function report_progress {
  while read count ; do
    # mksh can't do floating point arithmetic, so emulate a fixed point calculation.
    (( permilles = 1000 * count / ${#otadexopt_cmds[@]} ))
    printf 'global_progress %d.%03d\n' $((permilles / 1000)) $((permilles % 1000)) >&${STATUS_FD}
  done
}

print_otadexopt_cmds | \
  /system/bin/otapreopt_chroot $STATUS_FD $TARGET_SLOT_SUFFIX | \
  report_progress

if [ "$DONE" = "OTA incomplete." ] ; then
  echo "$0: Incomplete."
else
  echo "$0: Complete or error."
fi

print -u${STATUS_FD} "global_progress 1.0"

exit 0
