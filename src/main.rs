extern crate peach_network;
#[macro_use]
extern crate log;
extern crate env_logger;

use std::process;

fn main() {
    // initalize the logger
    env_logger::init();

    // handle errors returned from `run`
    if let Err(e) = peach_network::run() {
        error!("Application error: {}", e);
        process::exit(1);
    }
}
