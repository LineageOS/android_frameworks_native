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

//! A Rust implementation of the evemu-record command from the [FreeDesktop evemu suite][evemu] of
//! tools.
//!
//! [evemu]: https://gitlab.freedesktop.org/libevdev/evemu

use std::cmp;
use std::error::Error;
use std::fs;
use std::io;
use std::io::{BufRead, Write};
use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use nix::sys::time::TimeVal;

mod evdev;

/// Records evdev events from an input device in a format compatible with the FreeDesktop evemu
/// library.
#[derive(Parser, Debug)]
struct Args {
    /// The path to the input device to record. If omitted, offers a list of devices to choose from.
    device: Option<PathBuf>,
    /// The file to save the recording to. Defaults to standard output.
    output_file: Option<PathBuf>,

    /// The base time that timestamps should be relative to (Android-specific extension)
    #[arg(long, value_enum, default_value_t = TimestampBase::FirstEvent)]
    timestamp_base: TimestampBase,
}

#[derive(Clone, Debug, ValueEnum)]
enum TimestampBase {
    /// The first event received from the device.
    FirstEvent,

    /// The time when the system booted.
    Boot,
}

fn get_choice(max: u32) -> u32 {
    fn read_u32() -> Result<u32, std::num::ParseIntError> {
        io::stdin().lock().lines().next().unwrap().unwrap().parse::<u32>()
    }
    let mut choice = read_u32();
    while choice.is_err() || choice.clone().unwrap() > max {
        eprint!("Enter a number between 0 and {max} inclusive: ");
        choice = read_u32();
    }
    choice.unwrap()
}

fn pick_input_device() -> Result<PathBuf, io::Error> {
    eprintln!("Available devices:");
    let mut entries =
        fs::read_dir("/dev/input")?.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    let mut highest_number = 0;
    for entry in entries {
        let path = entry.path();
        let file_name = path.file_name().unwrap().to_str().unwrap();
        if path.is_dir() || !file_name.starts_with("event") {
            continue;
        }
        let number = file_name.strip_prefix("event").unwrap().parse::<u32>();
        if number.is_err() {
            continue;
        }
        let number = number.unwrap();
        match evdev::Device::open(path.as_path()) {
            Ok(dev) => {
                highest_number = cmp::max(highest_number, number);
                eprintln!(
                    "{}:\t{}",
                    path.display(),
                    dev.name().unwrap_or("[could not read name]".to_string()),
                );
            }
            Err(_) => {
                eprintln!("Couldn't open {}", path.display());
            }
        }
    }
    eprint!("Select the device event number [0-{highest_number}]: ");
    let choice = get_choice(highest_number);
    Ok(PathBuf::from(format!("/dev/input/event{choice}")))
}

fn print_device_description(
    device: &evdev::Device,
    output: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    // TODO(b/302297266): report LED and SW states, then bump the version to EVEMU 1.3.
    writeln!(output, "# EVEMU 1.2")?;
    writeln!(output, "N: {}", device.name()?)?;

    let ids = device.ids()?;
    writeln!(
        output,
        "I: {:04x} {:04x} {:04x} {:04x}",
        ids.bus_type, ids.vendor, ids.product, ids.version,
    )?;

    fn print_in_8_byte_chunks(
        output: &mut impl Write,
        prefix: &str,
        data: &Vec<u8>,
    ) -> Result<(), io::Error> {
        for (i, byte) in data.iter().enumerate() {
            if i % 8 == 0 {
                write!(output, "{prefix}")?;
            }
            write!(output, " {:02x}", byte)?;
            if (i + 1) % 8 == 0 {
                writeln!(output)?;
            }
        }
        if data.len() % 8 != 0 {
            for _ in (data.len() % 8)..8 {
                write!(output, " 00")?;
            }
            writeln!(output)?;
        }
        Ok(())
    }

    let props = device.properties_bitmap()?;
    print_in_8_byte_chunks(output, "P:", &props)?;

    // The SYN event type can't be queried through the EVIOCGBIT ioctl, so just hard-code it to
    // SYN_REPORT, SYN_CONFIG, and SYN_DROPPED.
    writeln!(output, "B: 00 0b 00 00 00 00 00 00 00")?;
    for event_type in evdev::EVENT_TYPES_WITH_BITMAPS {
        let bits = device.bitmap_for_event_type(event_type)?;
        print_in_8_byte_chunks(output, format!("B: {:02x}", event_type as u16).as_str(), &bits)?;
    }

    for axis in device.supported_axes_of_type(evdev::EventType::ABS)? {
        let info = device.absolute_axis_info(axis)?;
        writeln!(
            output,
            "A: {axis:02x} {} {} {} {} {}",
            info.minimum, info.maximum, info.fuzz, info.flat, info.resolution
        )?;
    }
    Ok(())
}

fn print_events(
    device: &evdev::Device,
    output: &mut impl Write,
    timestamp_base: TimestampBase,
) -> Result<(), Box<dyn Error>> {
    fn print_event(output: &mut impl Write, event: &evdev::InputEvent) -> Result<(), io::Error> {
        // TODO(b/302297266): Translate events into human-readable names and add those as comments.
        writeln!(
            output,
            "E: {}.{:06} {:04x} {:04x} {:04}",
            event.time.tv_sec(),
            event.time.tv_usec(),
            event.type_,
            event.code,
            event.value,
        )?;
        Ok(())
    }
    let event = device.read_event()?;
    let start_time = match timestamp_base {
        // Due to a bug in the C implementation of evemu-play [0] that has since become part of the
        // API, the timestamp of the first event in a recording shouldn't be exactly 0.0 seconds,
        // so offset it by 1µs.
        //
        // [0]: https://gitlab.freedesktop.org/libevdev/evemu/-/commit/eba96a4d2be7260b5843e65c4b99c8b06a1f4c9d
        TimestampBase::FirstEvent => event.time - TimeVal::new(0, 1),
        TimestampBase::Boot => TimeVal::new(0, 0),
    };
    print_event(output, &event.offset_time_by(start_time))?;
    loop {
        let event = device.read_event()?;
        print_event(output, &event.offset_time_by(start_time))?;
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let device_path = args.device.unwrap_or_else(|| pick_input_device().unwrap());

    let device = evdev::Device::open(device_path.as_path())?;
    let mut output = match args.output_file {
        Some(path) => Box::new(fs::File::create(path)?) as Box<dyn Write>,
        None => Box::new(io::stdout().lock()),
    };
    print_device_description(&device, &mut output)?;
    print_events(&device, &mut output, args.timestamp_base)?;
    Ok(())
}
