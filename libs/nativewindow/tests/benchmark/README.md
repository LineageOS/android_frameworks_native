# libnativewindow Benchmarks

This directory contains benchmarks for the C++ and Rust variants of
libnativewindow.

## Running

It is currently a little tricky to get statistics from Rust benchmarks directly
from tradefed. But we can hack it by using atest to build/push, then running
the benchmarks by hand to get stats.

```
  $ atest nativewindow_buffer_benchmarks_rs nativewindow_buffer_benchmarks_cc -d
  $ adb shell /data/local/tmp/nativewindow_buffer_benchmarks_cc/x86_64/nativewindow_buffer_benchmarks_cc
  $ adb shell /data/local/tmp/nativewindow_buffer_benchmarks_rs/x86_64/nativewindow_buffer_benchmarks_rs --bench
```

## Results

On a remote emulator, the results we see from the benchmarks from Rust and C++
seem to be roughly equivalent! Allocating/deallocating a 720p buffer takes
~2.3ms on each.
