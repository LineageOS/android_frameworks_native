/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_AUDIOMANAGER_H
#define ANDROID_AUDIOMANAGER_H

namespace android {

// must be kept in sync with definitions in AudioPlaybackConfiguration.java
#define PLAYER_PIID_INVALID -1

typedef enum {
    PLAYER_TYPE_SLES_AUDIOPLAYER_BUFFERQUEUE = 11,
    PLAYER_TYPE_SLES_AUDIOPLAYER_URI_FD = 12,
    PLAYER_TYPE_AAUDIO = 13,
    PLAYER_TYPE_HW_SOURCE = 14,
    PLAYER_TYPE_EXTERNAL_PROXY = 15,
} player_type_t;

typedef enum {
    PLAYER_STATE_UNKNOWN  = -1,
    PLAYER_STATE_RELEASED = 0,
    PLAYER_STATE_IDLE     = 1,
    PLAYER_STATE_STARTED  = 2,
    PLAYER_STATE_PAUSED   = 3,
    PLAYER_STATE_STOPPED  = 4,
    PLAYER_UPDATE_DEVICE_ID = 5,
    PLAYER_UPDATE_PORT_ID = 6,
    PLAYER_UPDATE_MUTED = 7,
    PLAYER_UPDATE_FORMAT = 8,
} player_state_t;

static constexpr char
    kExtraPlayerEventSpatializedKey[] = "android.media.extra.PLAYER_EVENT_SPATIALIZED";
static constexpr char
    kExtraPlayerEventSampleRateKey[] = "android.media.extra.PLAYER_EVENT_SAMPLE_RATE";
static constexpr char
    kExtraPlayerEventChannelMaskKey[] = "android.media.extra.PLAYER_EVENT_CHANNEL_MASK";

static constexpr char
    kExtraPlayerEventMuteKey[] = "android.media.extra.PLAYER_EVENT_MUTE";
enum {
    PLAYER_MUTE_MASTER = (1 << 0),
    PLAYER_MUTE_STREAM_VOLUME = (1 << 1),
    PLAYER_MUTE_STREAM_MUTED = (1 << 2),
    PLAYER_MUTE_PLAYBACK_RESTRICTED = (1 << 3),
    PLAYER_MUTE_CLIENT_VOLUME = (1 << 4),
    PLAYER_MUTE_VOLUME_SHAPER = (1 << 5),
};

struct mute_state_t {
    /** Flag used when the master volume is causing the mute state. */
    bool muteFromMasterMute = false;
    /** Flag used when the stream volume is causing the mute state. */
    bool muteFromStreamVolume = false;
    /** Flag used when the stream muted is causing the mute state. */
    bool muteFromStreamMuted = false;
    /** Flag used when playback is restricted by AppOps manager with OP_PLAY_AUDIO. */
    bool muteFromPlaybackRestricted = false;
    /** Flag used when audio track was muted by client volume. */
    bool muteFromClientVolume = false;
     /** Flag used when volume is muted by volume shaper. */
    bool muteFromVolumeShaper = false;

    explicit operator int() const
    {
        int result = muteFromMasterMute * PLAYER_MUTE_MASTER;
        result |= muteFromStreamVolume * PLAYER_MUTE_STREAM_VOLUME;
        result |= muteFromStreamMuted * PLAYER_MUTE_STREAM_MUTED;
        result |= muteFromPlaybackRestricted * PLAYER_MUTE_PLAYBACK_RESTRICTED;
        result |= muteFromClientVolume * PLAYER_MUTE_CLIENT_VOLUME;
        result |= muteFromVolumeShaper * PLAYER_MUTE_VOLUME_SHAPER;
        return result;
    }

    bool operator==(const mute_state_t& other) const
    {
        return static_cast<int>(*this) == static_cast<int>(other);
    }
};

// must be kept in sync with definitions in AudioManager.java
#define RECORD_RIID_INVALID -1

typedef enum {
    RECORDER_STATE_UNKNOWN  = -1,
    RECORDER_STATE_STARTED  = 0,
    RECORDER_STATE_STOPPED  = 1,
} recorder_state_t;

}; // namespace android

#endif // ANDROID_AUDIOMANAGER_H
