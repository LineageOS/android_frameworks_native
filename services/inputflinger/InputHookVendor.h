#ifndef __INPUTHOOK_VENDOR__H__
#define __INPUTHOOK_VENDOR__H__
#include "EventHub.h"

extern void inputhook_vendor_init(android::EventHub*);
extern void inputhook_vendor_touchrotate(int32_t*, int32_t*, int32_t*);
#endif /* __INPUTHOOK_VENDOR__H__ */
