// Copyright (C) 2024 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! sfdo: Make surface flinger do things
use android_gui::{aidl::android::gui::ISurfaceComposer::ISurfaceComposer, binder};
use clap::{Parser, Subcommand};
use std::fmt::Debug;

const SERVICE_IDENTIFIER: &str = "SurfaceFlingerAIDL";

fn print_result<T, E>(function_name: &str, res: Result<T, E>)
where
    E: Debug,
{
    match res {
        Ok(_) => println!("{}: Operation successful!", function_name),
        Err(err) => println!("{}: Operation failed: {:?}", function_name, err),
    }
}

fn parse_toggle(toggle_value: &str) -> Option<bool> {
    let positive = ["1", "true", "y", "yes", "on", "enabled", "show"];
    let negative = ["0", "false", "n", "no", "off", "disabled", "hide"];

    let word = toggle_value.to_lowercase(); // Case-insensitive comparison

    if positive.contains(&word.as_str()) {
        Some(true)
    } else if negative.contains(&word.as_str()) {
        Some(false)
    } else {
        None
    }
}

#[derive(Parser)]
#[command(version = "0.1", about = "Execute SurfaceFlinger internal commands.")]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "[optional(--delay)] Perform a debug flash.")]
    DebugFlash {
        #[arg(short, long, default_value_t = 0)]
        delay: i32,
    },

    #[command(
        about = "state = [enabled | disabled] When enabled, it disables Hardware Overlays, \
                      and routes all window composition to the GPU. This can help check if \
                      there is a bug in HW Composer."
    )]
    ForceClientComposition { state: Option<String> },

    #[command(about = "state = [hide | show], displays the framerate in the top left corner.")]
    FrameRateIndicator { state: Option<String> },

    #[command(about = "Force composite ahead of next VSYNC.")]
    ScheduleComposite,

    #[command(about = "Force commit ahead of next VSYNC.")]
    ScheduleCommit,
}

/// sfdo command line tool
///
/// sfdo allows you to call different functions from the SurfaceComposer using
/// the adb shell.
fn main() {
    binder::ProcessState::start_thread_pool();
    let composer_service = match binder::get_interface::<dyn ISurfaceComposer>(SERVICE_IDENTIFIER) {
        Ok(service) => service,
        Err(err) => {
            eprintln!("Unable to connect to ISurfaceComposer: {}", err);
            return;
        }
    };

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::FrameRateIndicator { state }) => {
            if let Some(op_state) = state {
                let toggle = parse_toggle(op_state);
                match toggle {
                    Some(true) => {
                        let res = composer_service.enableRefreshRateOverlay(true);
                        print_result("enableRefreshRateOverlay", res);
                    }
                    Some(false) => {
                        let res = composer_service.enableRefreshRateOverlay(false);
                        print_result("enableRefreshRateOverlay", res);
                    }
                    None => {
                        eprintln!("Invalid state: {}, choices are [hide | show]", op_state);
                    }
                }
            } else {
                eprintln!("No state, choices are [hide | show]");
            }
        }
        Some(Commands::DebugFlash { delay }) => {
            let res = composer_service.setDebugFlash(*delay);
            print_result("setDebugFlash", res);
        }
        Some(Commands::ScheduleComposite) => {
            let res = composer_service.scheduleComposite();
            print_result("scheduleComposite", res);
        }
        Some(Commands::ScheduleCommit) => {
            let res = composer_service.scheduleCommit();
            print_result("scheduleCommit", res);
        }
        Some(Commands::ForceClientComposition { state }) => {
            if let Some(op_state) = state {
                let toggle = parse_toggle(op_state);
                match toggle {
                    Some(true) => {
                        let res = composer_service.forceClientComposition(true);
                        print_result("forceClientComposition", res);
                    }
                    Some(false) => {
                        let res = composer_service.forceClientComposition(false);
                        print_result("forceClientComposition", res);
                    }
                    None => {
                        eprintln!("Invalid state: {}, choices are [enabled | disabled]", op_state);
                    }
                }
            } else {
                eprintln!("No state, choices are [enabled | disabled]");
            }
        }
        None => {
            println!("Execute SurfaceFlinger internal commands.");
            println!("run `adb shell sfdo help` for more to view the commands.");
            println!("run `adb shell sfdo [COMMAND] --help` for more info on the command.");
        }
    }
}
