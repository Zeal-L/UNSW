use env_logger;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};

// RUST_LOG=trace cargo run

struct Position {
    x: f32,
    y: f32,
}

fn main() {
    env_logger::init();

    let pos = Position {
        x: 3.234,
        y: -1.223,
    };

    info!("New position: x: {}, y: {}", pos.x, pos.y);
    info!(target: "app_events", "New position: x: {}, y: {}", pos.x, pos.y);
}
