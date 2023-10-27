/*
 * Copyright 2023 The Android Open Source Project
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

//! Wrappers for the Linux evdev APIs.

use std::fs::File;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

use libc::c_int;
use nix::sys::time::TimeVal;

pub const SYN_CNT: usize = 0x10;
pub const KEY_CNT: usize = 0x300;
pub const REL_CNT: usize = 0x10;
pub const ABS_CNT: usize = 0x40;
pub const MSC_CNT: usize = 0x08;
pub const SW_CNT: usize = 0x11;
pub const LED_CNT: usize = 0x10;
pub const SND_CNT: usize = 0x08;
pub const REP_CNT: usize = 0x02;

// Disable naming warnings, as these are supposed to match the EV_ constants in input-event-codes.h.
#[allow(non_camel_case_types)]
// Some of these types aren't referenced for evemu purposes, but are included for completeness.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum EventType {
    SYN = 0x00,
    KEY = 0x01,
    REL = 0x02,
    ABS = 0x03,
    MSC = 0x04,
    SW = 0x05,
    LED = 0x11,
    SND = 0x12,
    REP = 0x14,
    FF = 0x15,
    PWR = 0x16,
    FF_STATUS = 0x17,
}

impl EventType {
    fn code_count(&self) -> usize {
        match self {
            EventType::SYN => SYN_CNT,
            EventType::KEY => KEY_CNT,
            EventType::REL => REL_CNT,
            EventType::ABS => ABS_CNT,
            EventType::MSC => MSC_CNT,
            EventType::SW => SW_CNT,
            EventType::LED => LED_CNT,
            EventType::SND => SND_CNT,
            EventType::REP => REP_CNT,
            _ => {
                panic!("Event type {self:?} does not have a defined code count.");
            }
        }
    }
}

pub const EVENT_TYPES_WITH_BITMAPS: [EventType; 7] = [
    EventType::KEY,
    EventType::REL,
    EventType::ABS,
    EventType::MSC,
    EventType::SW,
    EventType::LED,
    EventType::SND,
];

const INPUT_PROP_CNT: usize = 32;

/// The `ioctl_*!` macros create public functions by default, so this module makes them private.
mod ioctl {
    use nix::{ioctl_read, ioctl_read_buf};

    ioctl_read!(eviocgid, b'E', 0x02, super::DeviceId);
    ioctl_read_buf!(eviocgname, b'E', 0x06, u8);
    ioctl_read_buf!(eviocgprop, b'E', 0x09, u8);
}

#[derive(Default)]
#[repr(C)]
pub struct DeviceId {
    pub bus_type: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
}

#[derive(Default)]
#[repr(C)]
pub struct AbsoluteAxisInfo {
    pub value: i32,
    pub minimum: i32,
    pub maximum: i32,
    pub fuzz: i32,
    pub flat: i32,
    pub resolution: i32,
}

#[repr(C)]
pub struct InputEvent {
    pub time: TimeVal,
    pub type_: u16,
    pub code: u16,
    pub value: i32,
}

impl InputEvent {
    pub fn offset_time_by(&self, offset: TimeVal) -> InputEvent {
        InputEvent { time: self.time - offset, ..*self }
    }
}

impl Default for InputEvent {
    fn default() -> Self {
        InputEvent { time: TimeVal::new(0, 0), type_: 0, code: 0, value: 0 }
    }
}

/// An object representing an input device using Linux's evdev protocol.
pub struct Device {
    fd: OwnedFd,
}

/// # Safety
///
/// `ioctl` must be safe to call with the given file descriptor and a pointer to a buffer of
/// `initial_buf_size` `u8`s.
unsafe fn buf_from_ioctl(
    ioctl: unsafe fn(c_int, &mut [u8]) -> nix::Result<c_int>,
    fd: &OwnedFd,
    initial_buf_size: usize,
) -> Result<Vec<u8>, nix::errno::Errno> {
    let mut buf = vec![0; initial_buf_size];
    // SAFETY:
    // Here we're relying on the safety guarantees for `ioctl` made by the caller.
    match unsafe { ioctl(fd.as_raw_fd(), buf.as_mut_slice()) } {
        Ok(len) if len < 0 => {
            panic!("ioctl returned invalid length {len}");
        }
        Ok(len) => {
            buf.truncate(len as usize);
            Ok(buf)
        }
        Err(err) => Err(err),
    }
}

impl Device {
    /// Opens a device from the evdev node at the given path.
    pub fn open(path: &Path) -> io::Result<Device> {
        Ok(Device { fd: OwnedFd::from(File::open(path)?) })
    }

    /// Returns the name of the device, as set by the relevant kernel driver.
    pub fn name(&self) -> Result<String, nix::errno::Errno> {
        // There's no official maximum length for evdev device names. The Linux HID driver
        // currently supports names of at most 151 bytes (128 from the device plus a suffix of up
        // to 23 bytes). 256 seems to be the buffer size most commonly used in evdev bindings, so
        // we use it here.
        //
        // SAFETY:
        // We know that fd is a valid file descriptor as it comes from a File that we have open.
        //
        // The ioctl_read_buf macro prevents the retrieved data from overflowing the buffer created
        // by buf_from_ioctl by passing in the size to the ioctl, meaning that the kernel's
        // str_to_user function will truncate the string to that length.
        let mut buf = unsafe { buf_from_ioctl(ioctl::eviocgname, &self.fd, 256)? };
        assert!(!buf.is_empty(), "buf is too short for an empty null-terminated string");
        assert_eq!(buf.pop().unwrap(), 0, "buf is not a null-terminated string");
        Ok(String::from_utf8_lossy(buf.as_slice()).into_owned())
    }

    pub fn ids(&self) -> Result<DeviceId, nix::errno::Errno> {
        let mut ids = DeviceId::default();
        // SAFETY:
        // We know that fd is a valid file descriptor as it comes from a File that we have open.
        //
        // We know that the pointer to ids is valid because we just allocated it.
        unsafe { ioctl::eviocgid(self.fd.as_raw_fd(), &mut ids) }.map(|_| ids)
    }

    pub fn properties_bitmap(&self) -> Result<Vec<u8>, nix::errno::Errno> {
        let buf_size = (INPUT_PROP_CNT + 7) / 8;
        // SAFETY:
        // We know that fd is a valid file descriptor as it comes from a File that we have open.
        //
        // The ioctl_read_buf macro prevents the retrieved data from overflowing the buffer created
        // by buf_from_ioctl by passing in the size to the ioctl, meaning that the kernel's
        // str_to_user function will truncate the string to that length.
        unsafe { buf_from_ioctl(ioctl::eviocgprop, &self.fd, buf_size) }
    }

    pub fn bitmap_for_event_type(&self, event_type: EventType) -> nix::Result<Vec<u8>> {
        let buf_size = (event_type.code_count() + 7) / 8;
        let mut buf = vec![0; buf_size];

        // The EVIOCGBIT ioctl can't be bound using ioctl_read_buf! like the others, since it uses
        // part of its ioctl code as an additional parameter, for the event type. Hence this unsafe
        // block is a manual expansion of ioctl_read_buf!.
        //
        // SAFETY:
        // We know that fd is a valid file descriptor as it comes from a File that we have open.
        //
        // We prevent the retrieved data from overflowing buf by passing in the size of buf to the
        // ioctl, meaning that the kernel's str_to_user function will truncate the string to that
        // length. We also panic if the ioctl returns a length longer than buf, hopefully before the
        // overflow can do any damage.
        match nix::errno::Errno::result(unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                nix::request_code_read!(b'E', 0x20 + event_type as u16, buf.len())
                    as nix::sys::ioctl::ioctl_num_type,
                buf.as_mut_ptr(),
            )
        }) {
            Ok(len) if len < 0 => {
                panic!("EVIOCGBIT returned invalid length {len} for event type {event_type:?}");
            }
            Ok(len) => {
                buf.truncate(len as usize);
                Ok(buf)
            }
            Err(err) => Err(err),
        }
    }

    pub fn supported_axes_of_type(&self, event_type: EventType) -> nix::Result<Vec<u16>> {
        let mut axes = Vec::new();
        for (i, byte_ref) in self.bitmap_for_event_type(event_type)?.iter().enumerate() {
            let mut byte = *byte_ref;
            for j in 0..8 {
                if byte & 1 == 1 {
                    axes.push((i * 8 + j) as u16);
                }
                byte >>= 1;
            }
        }
        Ok(axes)
    }

    pub fn absolute_axis_info(&self, axis: u16) -> nix::Result<AbsoluteAxisInfo> {
        let mut info = AbsoluteAxisInfo::default();
        // The EVIOCGABS ioctl can't be bound using ioctl_read! since it uses part of its ioctl code
        // as an additional parameter, for the axis code. Hence this unsafe block is a manual
        // expansion of ioctl_read!.
        //
        // SAFETY:
        // We know that fd is a valid file descriptor as it comes from a File that we have open.
        //
        // We know that the pointer to info is valid because we just allocated it.
        nix::errno::Errno::result(unsafe {
            nix::libc::ioctl(
                self.fd.as_raw_fd(),
                nix::request_code_read!(b'E', 0x40 + axis, mem::size_of::<AbsoluteAxisInfo>()),
                &mut info,
            )
        })
        .map(|_| info)
    }

    pub fn read_event(&self) -> nix::Result<InputEvent> {
        let mut event = InputEvent::default();

        // SAFETY:
        // We know that fd is a valid file descriptor as it comes from a File that we have open.
        //
        // We know that the pointer to event is valid because we just allocated it, and that the
        // data structures match up because InputEvent is repr(C) and all its members are repr(C)
        // or primitives that support all representations without niches.
        nix::errno::Errno::result(unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                &mut event as *mut _ as *mut std::ffi::c_void,
                mem::size_of::<InputEvent>(),
            )
        })
        .map(|_| event)
    }
}
