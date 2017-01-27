#ifndef ANDROID_DVR_PLATFORM_DEFINES_H_
#define ANDROID_DVR_PLATFORM_DEFINES_H_

// Platform-specific macros and defines.

// QCOM's GRALLOC_USAGE_PRIVATE_ALLOC_UBWC usage bit.
#define GRALLOC_USAGE_QCOM_FRAMEBUFFER_COMPRESSION GRALLOC_USAGE_PRIVATE_1

// QCOM bit to use the ADSP heap. This carveout heap is accessible to Linux,
// Hexagon DSPs, and the GPU.
#define GRALLOC_USAGE_PRIVATE_ADSP_HEAP 0x01000000

// Force a gralloc buffer to get the uncached ION option set.
#define GRALLOC_USAGE_PRIVATE_UNCACHED 0x02000000

#endif  // ANDROID_DVR_PLATFORM_DEFINES_H_
