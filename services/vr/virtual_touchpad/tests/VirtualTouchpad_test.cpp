#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <linux/input.h>

#include "EvdevInjector.h"
#include "VirtualTouchpad.h"

namespace android {
namespace dvr {

namespace {

class UInputForTesting : public EvdevInjector::UInput {
 public:
  void WriteInputEvent(uint16_t type, uint16_t code, int32_t value) {
    struct input_event event;
    memset(&event, 0, sizeof(event));
    event.type = type;
    event.code = code;
    event.value = value;
    Write(&event, sizeof (event));
  }
};

// Recording test implementation of UInput.
//
class UInputRecorder : public UInputForTesting {
 public:
  UInputRecorder() {}
  virtual ~UInputRecorder() {}

  const std::string& GetString() const { return s_; }
  void Reset() { s_.clear(); }

  // UInput overrides:

  int Open() override {
    s_ += "o;";
    return 0;
  }

  int Close() override {
    s_ += "c;";
    return 0;
  }

  int Write(const void* buf, size_t count) override {
    s_ += "w(";
    s_ += Encode(&count, sizeof(count));
    s_ += ",";
    s_ += Encode(buf, count);
    s_ += ");";
    return 0;
  }

  int IoctlVoid(int request) override {
    s_ += "i(";
    s_ += Encode(&request, sizeof(request));
    s_ += ");";
    return 0;
  }

  int IoctlSetInt(int request, int value) override {
    s_ += "i(";
    s_ += Encode(&request, sizeof(request));
    s_ += ",";
    s_ += Encode(&value, sizeof(value));
    s_ += ");";
    return 0;
  }

 private:
  std::string s_;

  std::string Encode(const void* buf, size_t count) {
    const char* in = static_cast<const char*>(buf);
    char out[2 * count + 1];
    for (size_t i = 0; i < count; ++i) {
      snprintf(&out[2 * i], 3, "%02X", in[i]);
    }
    return out;
  }
};

class EvdevInjectorForTesting : public EvdevInjector {
 public:
  EvdevInjectorForTesting(UInput& uinput) {
    SetUInputForTesting(&uinput);
  }
  const uinput_user_dev* GetUiDev() const { return GetUiDevForTesting(); }
};

class VirtualTouchpadForTesting : public VirtualTouchpad {
 public:
  VirtualTouchpadForTesting(EvdevInjector& injector) {
    SetEvdevInjectorForTesting(&injector);
  }
};

void DumpDifference(const char* expect, const char* actual) {
  printf("  common: ");
  while (*expect && *expect == *actual) {
    putchar(*expect);
    ++expect;
    ++actual;
  }
  printf("\n  expect: %s\n", expect);
  printf("  actual: %s\n", actual);
}

}  // anonymous namespace

class VirtualTouchpadTest : public testing::Test {
};

TEST_F(VirtualTouchpadTest, Goodness) {
  UInputRecorder expect;
  UInputRecorder record;
  EvdevInjectorForTesting injector(record);
  VirtualTouchpadForTesting touchpad(injector);

  const int initialization_status = touchpad.Initialize();
  EXPECT_EQ(0, initialization_status);

  // Check some aspects of uinput_user_dev.
  const uinput_user_dev* uidev = injector.GetUiDev();
  for (int i = 0; i < ABS_CNT; ++i) {
    EXPECT_EQ(0, uidev->absmin[i]);
    EXPECT_EQ(0, uidev->absfuzz[i]);
    EXPECT_EQ(0, uidev->absflat[i]);
    if (i != ABS_MT_POSITION_X && i != ABS_MT_POSITION_Y && i != ABS_MT_SLOT) {
      EXPECT_EQ(0, uidev->absmax[i]);
    }
  }
  const int32_t width = 1 + uidev->absmax[ABS_MT_POSITION_X];
  const int32_t height = 1 + uidev->absmax[ABS_MT_POSITION_Y];
  const int32_t slots = uidev->absmax[ABS_MT_SLOT];

  // Check the system calls performed by initialization.
  // From ConfigureBegin():
  expect.Open();
  // From ConfigureInputProperty(INPUT_PROP_DIRECT):
  expect.IoctlSetInt(UI_SET_PROPBIT, INPUT_PROP_DIRECT);
  // From ConfigureMultiTouchXY(0, 0, kWidth - 1, kHeight - 1):
  expect.IoctlSetInt(UI_SET_EVBIT, EV_ABS);
  expect.IoctlSetInt(UI_SET_ABSBIT, ABS_MT_POSITION_X);
  expect.IoctlSetInt(UI_SET_ABSBIT, ABS_MT_POSITION_Y);
  // From ConfigureAbsSlots(kSlots):
  expect.IoctlSetInt(UI_SET_ABSBIT, ABS_MT_SLOT);
  // From ConfigureKey(BTN_TOUCH):
  expect.IoctlSetInt(UI_SET_EVBIT, EV_KEY);
  expect.IoctlSetInt(UI_SET_KEYBIT, BTN_TOUCH);
  // From ConfigureEnd():
  expect.Write(uidev, sizeof (uinput_user_dev));
  expect.IoctlVoid(UI_DEV_CREATE);
  EXPECT_EQ(expect.GetString(), record.GetString());

  expect.Reset();
  record.Reset();
  int touch_status = touchpad.Touch(0, 0, 0);
  EXPECT_EQ(0, touch_status);
  expect.WriteInputEvent(EV_ABS, ABS_MT_SLOT, 0);
  expect.WriteInputEvent(EV_ABS, ABS_MT_TRACKING_ID, 0);
  expect.WriteInputEvent(EV_ABS, ABS_MT_POSITION_X, 0);
  expect.WriteInputEvent(EV_ABS, ABS_MT_POSITION_Y, 0);
  expect.WriteInputEvent(EV_SYN, SYN_REPORT, 0);
  EXPECT_EQ(expect.GetString(), record.GetString());

  expect.Reset();
  record.Reset();
  touch_status = touchpad.Touch(0.25f, 0.75f, 0.5f);
  EXPECT_EQ(0, touch_status);
  expect.WriteInputEvent(EV_ABS, ABS_MT_TRACKING_ID, 0);
  expect.WriteInputEvent(EV_ABS, ABS_MT_POSITION_X, 0.25f * width);
  expect.WriteInputEvent(EV_ABS, ABS_MT_POSITION_Y, 0.75f * height);
  expect.WriteInputEvent(EV_KEY, BTN_TOUCH, EvdevInjector::KEY_PRESS);
  expect.WriteInputEvent(EV_SYN, SYN_REPORT, 0);
  EXPECT_EQ(expect.GetString(), record.GetString());

  expect.Reset();
  record.Reset();
  touch_status = touchpad.Touch(1.0f, 1.0f, 1.0f);
  EXPECT_EQ(0, touch_status);
  expect.WriteInputEvent(EV_ABS, ABS_MT_TRACKING_ID, 0);
  expect.WriteInputEvent(EV_ABS, ABS_MT_POSITION_X, width);
  expect.WriteInputEvent(EV_ABS, ABS_MT_POSITION_Y, height);
  expect.WriteInputEvent(EV_SYN, SYN_REPORT, 0);
  EXPECT_EQ(expect.GetString(), record.GetString());

  expect.Reset();
  record.Reset();
  touch_status = touchpad.Touch(0.25f, 0.75f, -0.01f);
  EXPECT_EQ(0, touch_status);
  expect.WriteInputEvent(EV_KEY, BTN_TOUCH, EvdevInjector::KEY_RELEASE);
  expect.WriteInputEvent(EV_ABS, ABS_MT_TRACKING_ID, -1);
  expect.WriteInputEvent(EV_SYN, SYN_REPORT, 0);
  EXPECT_EQ(expect.GetString(), record.GetString());

  expect.Reset();
  record.Reset();
}

TEST_F(VirtualTouchpadTest, Badness) {
  UInputRecorder expect;
  UInputRecorder record;
  EvdevInjectorForTesting injector(record);
  VirtualTouchpadForTesting touchpad(injector);

  // Touch before initialization should return an error,
  // and should not result in any system calls.
  expect.Reset();
  record.Reset();
  int touch_status = touchpad.Touch(0.25f, 0.75f, -0.01f);
  EXPECT_NE(0, touch_status);
  EXPECT_EQ(expect.GetString(), record.GetString());

  expect.Reset();
  record.Reset();
  touchpad.Initialize();

  // Repeated initialization should return an error,
  // and should not result in any system calls.
  expect.Reset();
  record.Reset();
  const int initialization_status = touchpad.Initialize();
  EXPECT_NE(0, initialization_status);
  EXPECT_EQ(expect.GetString(), record.GetString());
}

}  // namespace dvr
}  // namespace android
