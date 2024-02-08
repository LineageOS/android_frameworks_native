# `evemu-record`

This is a Rust implementation of the `evemu-record` command from the [FreeDesktop project's evemu
suite][FreeDesktop]. It records the descriptor and events produced by a single input device in a
[simple text-based format][format] that can be replayed using the [`uinput` command on
Android][uinput] or the FreeDesktop evemu tools on other Linux-based platforms. It is included by
default with `userdebug` and `eng` builds of Android.

The command-line interface is the same as that of the FreeDesktop version, except for
Android-specific features. For usage instructions, run `evemu-record --help`.

## Usage example

From a computer connected to the device over ADB, you can start a recording:

```
$ adb shell evemu-record > my-recording.evemu
Available devices:
/dev/input/event0:      gpio_keys
/dev/input/event1:      s2mpg12-power-keys
/dev/input/event2:      NVTCapacitiveTouchScreen
/dev/input/event3:      NVTCapacitivePen
/dev/input/event4:      uinput-folio
/dev/input/event5:      ACME Touchpad
Select the device event number [0-5]: 5
```

...then use the input device for a while, and press Ctrl+C to finish. You will now have a
`my-recording.evemu` file that you can examine in a text editor. To replay it, use the [`uinput`
command][uinput]:

```
$ adb shell uinput - < my-recording.evemu
```

## Android-specific features

### Timestamp bases

By default, event timestamps are recorded relative to the time of the first event received during
the recording. Passing `--timestamp-base=boot` causes the timestamps to be recorded relative to the
system boot time instead. While this does not affect the playback of the recording, it can be useful
for matching recorded events with other logs that use such timestamps, such as `dmesg` or the
touchpad gesture debug logs emitted by `TouchpadInputMapper`.

[FreeDesktop]: https://gitlab.freedesktop.org/libevdev/evemu
[format]: https://gitlab.freedesktop.org/libevdev/evemu#device-description-format
[uinput]: https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/cmds/uinput/README.md
