#define LOG_TAG "libgvr_controller_shim"

#include <cutils/log.h>
#include <vr/gvr/capi/include/gvr_controller.h>
#include <vr/gvr/capi/include/gvr_types.h>

gvr_controller_context* gvr_controller_create_and_init(int32_t options,
                                                       gvr_context* context) {
  ALOGE("gvr_controller_create_and_init not implemented.");
  return nullptr;
}

gvr_controller_context* gvr_controller_create_and_init_android(
    JNIEnv* env, jobject android_context, jobject class_loader, int32_t options,
    gvr_context* context) {
  ALOGE("gvr_controller_create_and_init_android not implemented.");
  return nullptr;
}

void gvr_controller_destroy(gvr_controller_context** api) {
  ALOGE("gvr_controller_destroy not implemented.");
}

gvr_controller_state* gvr_controller_state_create() {
  ALOGE("gvr_controller_state_create not implemented.");
  return nullptr;
}

void gvr_controller_state_destroy(gvr_controller_state** state) {
  ALOGE("gvr_controller_state_destroy not implemented.");
}

void gvr_controller_state_update(gvr_controller_context* api, int32_t flags,
                                 gvr_controller_state* out_state) {
  ALOGE("gvr_controller_state_update not implemented.");
}

int64_t gvr_controller_state_get_last_button_timestamp(
    const gvr_controller_state* state) {
  ALOGE("gvr_controller_state_get_last_button_timestamp not implemented.");
  return 0;
}

bool gvr_controller_state_get_button_state(const gvr_controller_state* state,
                                           int32_t button) {
  ALOGE("gvr_controller_state_get_button_state not implemented.");
  return false;
}

bool gvr_controller_state_get_button_down(const gvr_controller_state* state,
                                          int32_t button) {
  ALOGE("gvr_controller_state_get_button_down not implemented.");
  return false;
}

bool gvr_controller_state_get_button_up(const gvr_controller_state* state,
                                        int32_t button) {
  ALOGE("gvr_controller_state_get_button_up not implemented.");
  return false;
}

bool gvr_controller_state_is_touching(const gvr_controller_state* state) {
  ALOGE("gvr_controller_state_is_touching not implemented.");
  return false;
}

gvr_vec2f gvr_controller_state_get_touch_pos(
    const gvr_controller_state* state) {
  ALOGE("gvr_controller_state_get_touch_pos not implemented.");
  return {0.0f, 0.0f};
}

bool gvr_controller_state_get_touch_down(const gvr_controller_state* state) {
  ALOGE("gvr_controller_state_get_touch_down not implemented.");
  return false;
}

bool gvr_controller_state_get_touch_up(const gvr_controller_state* state) {
  ALOGE("gvr_controller_state_get_touch_up not implemented.");
  return false;
}

int64_t gvr_controller_state_get_last_touch_timestamp(
    const gvr_controller_state* state) {
  ALOGE("gvr_controller_state_get_last_touch_timestamp not implemented.");
  return 0;
}

gvr_quatf gvr_controller_state_get_orientation(
    const gvr_controller_state* state) {
  ALOGE("gvr_controller_state_get_orientation not implemented.");
  return {0.0f, 0.0f, 0.0f, 0.0f};
}

int64_t gvr_controller_state_get_last_orientation_timestamp(
    const gvr_controller_state* state) {
  ALOGE("gvr_controller_state_get_last_orientation_timestamp not implemented.");
  return 0;
}

const char* gvr_controller_api_status_to_string(int32_t status) {
  ALOGE("gvr_controller_api_status_to_string not implemented.");
  return nullptr;
}

const char* gvr_controller_connection_state_to_string(int32_t state) {
  ALOGE("gvr_controller_connection_state_to_string not implemented.");
  return nullptr;
}

const char* gvr_controller_button_to_string(int32_t button) {
  ALOGE("gvr_controller_button_to_string not implemented.");
  return nullptr;
}

int32_t gvr_controller_get_default_options() {
  ALOGE("gvr_controller_get_default_options not implemented.");
  return 0;
}

void gvr_controller_pause(gvr_controller_context* api) {
  ALOGE("gvr_controller_pause not implemented.");
}

void gvr_controller_resume(gvr_controller_context* api) {
  ALOGE("gvr_controller_resume not implemented.");
}

int32_t gvr_controller_state_get_api_status(const gvr_controller_state* state) {
  return GVR_CONTROLLER_API_OK;
}

int32_t gvr_controller_state_get_connection_state(
    const gvr_controller_state* state) {
  return GVR_CONTROLLER_CONNECTED;
}

gvr_vec3f gvr_controller_state_get_gyro(const gvr_controller_state* state) {
  ALOGE("gvr_controller_state_get_gyro not implemented.");
  return {0.0, 0.0, 0.0};
}

gvr_vec3f gvr_controller_state_get_accel(const gvr_controller_state* state) {
  ALOGE("gvr_controller_state_get_accel not implemented.");
  return {0.0, 0.0, 0.0};
}

int64_t gvr_controller_state_get_last_gyro_timestamp(
    const gvr_controller_state* state) {
  ALOGE("gvr_controller_state_get_last_gyro_timestamp not implemented.");
  return 0;
}

int64_t gvr_controller_state_get_last_accel_timestamp(
    const gvr_controller_state* state) {
  ALOGE("gvr_controller_state_get_last_accel_timestamp not implemented.");
  return 0;
}

bool gvr_controller_state_get_recentered(const gvr_controller_state* state) {
  ALOGE("gvr_controller_state_get_recentered not implemented.");
  return false;
}

bool gvr_controller_state_get_recentering(const gvr_controller_state* state) {
  ALOGE("gvr_controller_state_get_recentering not implemented.");
  return false;
}
