#include "InputHookVendor.h"

/* InputHook vendor override stubs */

__attribute__ ((weak))
void inputhook_vendor_init(__attribute__((unused)) android::EventHub *ehub)
{
}

__attribute__ ((weak))
void inputhook_vendor_touchrotate(__attribute__((unused)) int32_t *width, __attribute__((unused))int32_t *height,
                                  __attribute__((unused)) int32_t *orientation)
{
}
