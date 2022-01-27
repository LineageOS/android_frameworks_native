# Fuzzers for SurfaceFlinger
## Table of contents
+ [SurfaceFlinger](#SurfaceFlinger)

# <a name="SurfaceFlinger"></a> Fuzzer for SurfaceFlinger

SurfaceFlinger supports the following data sources:
1. Pixel Formats (parameter name: `defaultCompositionPixelFormat`)
2. Data Spaces (parameter name: `defaultCompositionDataspace`)
3. Rotations (parameter name: `internalDisplayOrientation`)
3. Surface composer tags (parameter name: `onTransact`)

You can find the possible values in the fuzzer's source code.

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) surfaceflinger_fuzzer
```
2. To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/surfaceflinger_fuzzer/surfaceflinger_fuzzer
```
