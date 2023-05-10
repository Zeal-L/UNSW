use anyhow::{Error, Result};
use clap::Parser;
use iris_lib::{
    channel::ChannelList,
    command_handler::{command_handler, NextStep},
    connect::{ConnectionError, ConnectionManager},
    error::ServerError,
    types::{Nick, ParsedMessage, Reply, UnparsedMessage, SERVER_NAME},
    user::{User, UserList},
};

use chrono::{Local, Timelike};
use colored::*;

use std::io::Write;

use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    thread,
};
#[macro_use]
extern crate log;

#[derive(Parser)]
struct Arguments {
    #[clap(default_value = "127.0.0.1")]
    ip_address: IpAddr,

    #[clap(default_value = "6991")]
    port: u16,
}

pub fn run() {

}

// This is specifically to allow the use of write!() in logger format with a literal string
// purple = "\x1b[35m", which makes code more readable
#[allow(clippy::write_literal)]
fn main() -> Result<(), Error> {
    // ##################################################
    // # Initialize data structures and logger
    // ##################################################
    let user_list = Arc::new(Mutex::new(UserList::new()));
    let channel_list = Arc::new(Mutex::new(ChannelList::new()));
    pretty_env_logger::formatted_builder()
        .format(|buf, record| {
            let local_time = Local::now();
            let level_string = format!("{:5}", record.level());
            let level_color = match record.level() {
                log::Level::Error => Color::Red,
                log::Level::Warn => Color::Yellow,
                log::Level::Info => Color::Green,
                log::Level::Debug => Color::Magenta,
                log::Level::Trace => Color::Cyan,
            };
            let level_string = level_string.color(level_color);

            writeln!(
                buf,
                "{purple} [{hour:02}:{min:02}] {level} > {message}",
                purple = "\x1b[35m",
                hour = local_time.hour(),
                min = local_time.minute(),
                level = level_string,
                message = record.args(),
            )
        })
        .filter_level(log::LevelFilter::Debug)
        .init();

    // ##################################################
    // # Start the server
    // ##################################################
    let arguments = Arguments::parse();
    info!(
        "Launching {} at {}:{}",
        SERVER_NAME, arguments.ip_address, arguments.port
    );

    let mut connection_manager = ConnectionManager::launch(arguments.ip_address, arguments.port);
    loop {
        // This function call will block until a new client connects!
        let (mut conn_read, conn_write) = connection_manager.accept_new_connection();
        let curr_user_ip = conn_read.id().clone();
        let curr_user_ip_for_handle = conn_read.id().clone();
        info!("New connection from {}", conn_read.id());

        // Add the user to the user_list
        {
            let mut users = user_list.lock().map_err(ServerError::from)?;
            users.add_user(User::new(conn_read.id(), conn_write));
        }

        let mut users = user_list.clone();
        let mut channels = channel_list.clone();
        let handle = thread::spawn(move || -> Result<(), Error> {
            loop {
                // ##################################################
                // # Read the message from the client
                // # This will block until the client sends a message
                // ##################################################

                let message = match conn_read.read_message() {
                    Ok(message) => message,
                    Err(ConnectionError::ConnectionLost | ConnectionError::ConnectionClosed) => {
                        error!("Lost connection.");
                        break;
                    }
                    Err(_) => {
                        warn!("Invalid message received... ignoring message.");
                        continue;
                    }
                };

                // ##################################################
                // # After received a message, parsing it
                // ##################################################

                let curr_user_nick_name = {
                    let user_list = users.lock().map_err(ServerError::from)?;
                    let curr_user = user_list.get_user_by_ip(&curr_user_ip)?;
                    curr_user.get_nick_name()
                };

                let unparsed_msg = UnparsedMessage {
                    sender_nick: Nick(curr_user_nick_name.clone()),
                    message: message.as_str(),
                };

                match ParsedMessage::try_from(unparsed_msg) {
                    Ok(parsed_msg) => {
                        match command_handler(
                            &parsed_msg,
                            &mut users,
                            &mut channels,
                            &conn_read.id(),
                        ) {
                            Ok(next_step) => match next_step {
                                NextStep::Continue => {
                                    continue;
                                }
                                NextStep::Quit => {
                                    break;
                                }
                            },
                            Err(e) => {
                                warn!("Error while handling command: {}", e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        let mut user_list = users.lock().map_err(ServerError::from)?;
                        let curr_user = user_list.get_user_by_ip_mut(&conn_read.id())?;
                        let conn_write = curr_user.get_conn_write_mut();
                        match conn_write.write_message(Reply::Error(e).to_string().as_str()) {
                            Ok(_) => {
                                warn!(
                                    "Sent error message back to user: {}\n\t\t Error message: {}",
                                    curr_user_nick_name, e
                                );
                            }
                            Err(_) => {
                                error!("Lost connection.");
                                break;
                            }
                        }
                    }
                }
            }
            Ok(())
        });

        // ##################################################
        // # Spawn a new thread to handle the result of above thread
        // ##################################################
        let users = user_list.clone();
        let channels = channel_list.clone();
        thread::spawn(move || -> Result<(), Error> {
            let result = handle.join();

            let curr_user_nick_name = {
                let user_list = users.lock().map_err(ServerError::from)?;
                let curr_user = user_list.get_user_by_ip(&curr_user_ip_for_handle)?;
                curr_user.get_nick_name()
            };

            match result.unwrap() {
                Ok(_) => {
                    info!(
                        "User: {} - Thread exited successfully.",
                        curr_user_nick_name
                    );
                }
                Err(e) => {
                    error!(
                        "User: {} - Thread exited with error:\n\t\t {}",
                        curr_user_nick_name, e
                    );
                }
            }

            // Remove the user from all channel
            channels
                .lock()
                .map_err(ServerError::from)?
                .remove_user_from_all_channels(&curr_user_nick_name);

            // Remove the user from the user_list
            users
                .lock()
                .map_err(ServerError::from)?
                .remove_user_by_ip(&curr_user_ip_for_handle);

            Ok(())
        });
    }
}
