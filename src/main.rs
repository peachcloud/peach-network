use std::process;

use log::error;

fn main() {
    // initalize the logger
    env_logger::init();

    // handle errors returned from `run`
    if let Err(e) = peach_network::run() {
        error!("Application error: {}", e);
        process::exit(1);
    }
}
