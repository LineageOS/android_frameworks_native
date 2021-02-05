# This script captures MSKP files from RenderEngine in a connected device.
# this only functions when RenderEngine uses the Skia backend.
# it triggers code in SkiaCapture.cpp.

# for a newly flashed device, perform first time steps with
# record.sh rootandsetup

# record all frames that RenderEngine handles over the span of 2 seconds.
# record.sh 2000

if [ -z "$1" ]; then
    printf 'Usage:\n    record.sh rootandsetup\n'
    printf '    record.sh MILLISECONDS\n\n'
    exit 1
elif [ "$1" == "rootandsetup" ]; then
  # first time use requires these changes
  adb root
  adb shell setenforce 0
  adb shell setprop debug.renderengine.backend "skiagl"
  adb shell stop
  adb shell start
  exit 1;
fi

# name of the newest file in /data/user/ before starting
oldname=$(adb shell ls -cr /data/user/ | head -n 1)

# record frames for some number of milliseconds.
adb shell setprop debug.renderengine.capture_skia_ms $1

# give the device time to both record, and starting writing the file.
# Total time needed to write the file depends on how much data was recorded.
# the loop at the end waits for this.
sleep $(($1 / 1000 + 2));

# There is no guarantee that at least one frame passed through renderengine during that time
# but as far as I know it always at least writes a 0-byte file with a new name, unless it crashes
# the process it is recording.
# /data/user/re_skiacapture_56204430551705.mskp

# list the files here from newest to oldest, keep only the name of the newest.
name=$(adb shell ls -cr /data/user/ | head -n 1)
remote_path=/data/user/$name

if [[ $oldname = $name ]]; then
  echo "No new file written, probably no RenderEngine activity during recording period."
  exit 1
fi

# return the size of a file in bytes
adb_filesize() {
    adb shell "wc -c \"$1\"" 2> /dev/null | awk '{print $1}'
}

mskp_size=$(adb_filesize "/data/user/$name")
if [[ $mskp_size = "0" ]]; then
  echo "Empty file, probably no RenderEngine activity during recording period."
  exit 1
fi

spin() {
    case "$spin" in
         1) printf '\b|';;
         2) printf '\b\\';;
         3) printf '\b-';;
         *) printf '\b/';;
    esac
    spin=$(( ( ${spin:-0} + 1 ) % 4 ))
    sleep $1
}

printf "MSKP captured, Waiting for file serialization to finish.\n"

local_path=~/Downloads/$name

# wait for the file size to stop changing

timeout=$(( $(date +%s) + 300))
last_size='0' # output of last size check command
unstable=true # false once the file size stops changing
counter=0 # used to perform size check only 1/sec though we update spinner 20/sec
# loop until the file size is unchanged for 1 second.
while [ $unstable != 0 ] ; do
    spin 0.05
    counter=$(( $counter+1 ))
    if ! (( $counter % 20)) ; then
        new_size=$(adb_filesize "$remote_path")
        unstable=$(($new_size != $last_size))
        last_size=$new_size
    fi
    if [ $(date +%s) -gt $timeout ] ; then
        printf '\bTimed out.\n'
        exit 3
    fi
done
printf '\b'

printf "MSKP file serialized: %s\n" $(echo $last_size | numfmt --to=iec)

adb pull "$remote_path" "$local_path"
if ! [ -f "$local_path" ] ; then
    printf "something went wrong with `adb pull`."
    exit 4
fi
adb shell rm "$remote_path"
printf 'SKP saved to %s\n\n' "$local_path"