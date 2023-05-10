//! Integration tests for the iris-server

#![allow(non_snake_case)]
use std::env;
use std::process::{Child, Command, Stdio};

use bufstream::BufStream;
use std::{
    io::{BufRead, Write},
    net::{IpAddr, TcpStream},
};

struct Client {
    stream: TcpStream,
}

static mut SERVER_PORT: u16 = 18000;

fn increase_server_port() {
    unsafe {
        SERVER_PORT += 1;
    }
}

impl Client {
    fn new(port: u16) -> Self {
        let address: IpAddr = "127.0.0.1".to_string().parse().unwrap();
        let port: u16 = port.to_string().parse().unwrap();
        Self {
            stream: TcpStream::connect((address, port))
                .unwrap_or_else(|_| panic!("failed to connect to {address}:{port}")),
        }
    }

    fn send_line(&mut self, line: &str) {
        let mut stream_write = self.stream.try_clone().expect("failed to clone connection");
        let mut line = line.to_string();
        line.push_str("\r\n");
        if stream_write
            .write_all(line.as_bytes())
            .and_then(|_| stream_write.flush())
            .is_err()
        {
            eprintln!("writer failed");
        }
    }

    fn read_line(&mut self) -> String {
        let mut stream_read =
            BufStream::new(self.stream.try_clone().expect("failed to clone connection"));
        let mut line = String::new();
        stream_read
            .read_line(&mut line)
            .expect("failed to read from stream");
        line
    }
}

// Spawn the server process
fn start_server(port: u16) -> Child {
    // if command "6991 cargo run" exist, run it
    // otherwise, run "cargo run"
    let mut child = Command::new("6991")
        .args(&["cargo", "run", "--", "127.0.0.1", port.to_string().as_ref()])
        .stderr(Stdio::piped())
        .spawn()
        .or_else(|_| {
            Command::new("cargo")
            .args(&["run", "--", "127.0.0.1", port.to_string().as_ref()])
            .stderr(Stdio::piped())
            .spawn()
        }).expect("failed to execute process");

    let stderr = child.stderr.take().unwrap();
    let mut stderr_reader = std::io::BufReader::new(stderr);
    let mut stderr_line = String::new();

    // Wait for the server to start
    loop {
        stderr_reader
            .read_line(&mut stderr_line)
            .expect("failed to read from stderr");
        if stderr_line.contains("Launching iris-server") {
            break;
        }
    }

    child
}

// Terminate the server process
fn stop_server(server: Child) {
    let mut server = server;
    server.kill().expect("failed to kill child process");
    server.wait().expect("failed to wait for child process");

    std::thread::sleep(std::time::Duration::from_millis(1000));
}

// ##################################################
// # Testing NICK and USER Commands
// ##################################################

#[test]
fn test_NICK_and_USER_successfully() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    let server = start_server(port);

    let mut user_zeal = Client::new(port);

    user_zeal.send_line("NICK :zeal");
    user_zeal.send_line("USER _ _ _ :zeal");
    let expected = ":iris-server 001 zeal :Welcome to this server, zeal!";
    assert!(user_zeal.read_line().contains(expected));

    stop_server(server);
}

#[test]
fn test_NICK_ERR_NONICKNAMEGIVEN() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    let server = start_server(port);

    let mut client = Client::new(port);

    client.send_line("NICK");
    let expected = ":iris-server :iris-server 431 :No nickname given.";
    assert!(client.read_line().contains(expected));

    stop_server(server);
}

#[test]
fn test_NICK_ERR_ERRONEUSNICKNAME() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    let server = start_server(port);

    let mut client = Client::new(port);

    client.send_line("NICK :123");
    let expected = ":iris-server :iris-server 432 :Erroneus nickname";
    assert!(client.read_line().contains(expected));

    stop_server(server);
}

#[test]
fn test_NICK_ERR_NICKCOLLISION() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    let server = start_server(port);

    let mut user_zeal = Client::new(port);
    let mut client2 = Client::new(port);

    user_zeal.send_line("NICK :zeal");
    user_zeal.send_line("USER _ _ _ :zeal");
    let expected = ":iris-server 001 zeal :Welcome to this server, zeal!";
    assert!(user_zeal.read_line().contains(expected));

    client2.send_line("NICK :zeal");
    let expected = ":iris-server :iris-server 436 :Nickname collision";
    assert!(client2.read_line().contains(expected));

    stop_server(server);
}

#[test]
fn test_USER_ERR_NEEDMOREPARAMS() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    let server = start_server(port);

    let mut user_zeal = Client::new(port);

    user_zeal.send_line("USER _ _ :zeal");
    let expected = ":iris-server :iris-server 461 :Not enough parameters";
    assert!(user_zeal.read_line().contains(expected));

    stop_server(server);
}

// ##################################################
// # Testing PING and PONG Commands
// ##################################################

#[test]
fn test_PING_and_PONG_successfully() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    env::set_var("RUST_TEST_THREADS", "1");

    let user_zeal = start_server(port);

    let mut client = Client::new(port);

    client.send_line("NICK :zeal");
    client.send_line("USER _ _ _ :zeal");
    let expected = ":iris-server 001 zeal :Welcome to this server, zeal!";
    assert!(client.read_line().contains(expected));

    client.send_line("PING :Hello!");
    let expected = "PONG :Hello!";
    assert!(client.read_line().contains(expected));

    stop_server(user_zeal);
}

// ##################################################
// # Testing JOIN and QUIT Commands
// ##################################################

#[test]
fn test_JOIN_QUIT_successfully() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    let server = start_server(port);

    let mut user_zeal = Client::new(port);
    let mut user_james = Client::new(port);

    user_zeal.send_line("NICK :zeal");
    user_zeal.send_line("USER _ _ _ :zeal");
    let expected = ":iris-server 001 zeal :Welcome to this server, zeal!";
    assert!(user_zeal.read_line().contains(expected));

    user_zeal.send_line("JOIN #c");
    let expected = ":zeal JOIN #c";
    assert!(user_zeal.read_line().contains(expected));

    user_james.send_line("NICK :james");
    user_james.send_line("USER _ _ _ :james");
    let expected = ":iris-server 001 james :Welcome to this server, james!";
    assert!(user_james.read_line().contains(expected));

    user_james.send_line("JOIN #c");
    let expected = ":james JOIN #c";
    assert!(user_james.read_line().contains(expected));
    assert!(user_zeal.read_line().contains(expected));

    user_zeal.send_line("QUIT");
    let expected = ":zeal QUIT :zeal";
    assert!(user_james.read_line().contains(expected));

    stop_server(server);
}

#[test]
fn test_JOIN_QUIT_with_msg() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    let server = start_server(port);

    let mut user_zeal = Client::new(port);
    let mut user_james = Client::new(port);

    user_zeal.send_line("NICK :zeal");
    user_zeal.send_line("USER _ _ _ :zeal");
    let expected = ":iris-server 001 zeal :Welcome to this server, zeal!";
    assert!(user_zeal.read_line().contains(expected));

    user_zeal.send_line("JOIN #c");
    let expected = ":zeal JOIN #c";
    assert!(user_zeal.read_line().contains(expected));

    user_james.send_line("NICK :james");
    user_james.send_line("USER _ _ _ :james");
    let expected = ":iris-server 001 james :Welcome to this server, james!";
    assert!(user_james.read_line().contains(expected));

    user_james.send_line("JOIN #c");
    let expected = ":james JOIN #c";
    assert!(user_james.read_line().contains(expected));
    assert!(user_zeal.read_line().contains(expected));

    user_zeal.send_line("QUIT :Bye~");
    let expected = ":zeal QUIT :Bye~";
    assert!(user_james.read_line().contains(expected));

    stop_server(server);
}

#[test]
fn test_JOIN_ERR_NEEDMOREPARAMS() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    let server = start_server(port);

    let mut user_zeal = Client::new(port);

    user_zeal.send_line("NICK :zeal");
    user_zeal.send_line("USER _ _ _ :zeal");
    let expected = ":iris-server 001 zeal :Welcome to this server, zeal!";
    assert!(user_zeal.read_line().contains(expected));

    user_zeal.send_line("JOIN");
    let expected = ":iris-server :iris-server 461 :Not enough parameters";
    assert!(user_zeal.read_line().contains(expected));

    stop_server(server);
}

#[test]
fn test_JOIN_ERR_NOSUCHCHANNEL() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    let server = start_server(port);

    let mut user_zeal = Client::new(port);

    user_zeal.send_line("NICK :zeal");
    user_zeal.send_line("USER _ _ _ :zeal");
    let expected = ":iris-server 001 zeal :Welcome to this server, zeal!";
    assert!(user_zeal.read_line().contains(expected));

    user_zeal.send_line("JOIN 111");
    let expected = ":iris-server :iris-server 403 :No such channel";
    assert!(user_zeal.read_line().contains(expected));

    stop_server(server);
}

// ##################################################
// # Testing JOIN and PART Commands
// ##################################################

#[test]
fn test_PART_successfully() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    let server = start_server(port);

    let mut user_zeal = Client::new(port);
    let mut user_james = Client::new(port);

    user_zeal.send_line("NICK :zeal");
    user_zeal.send_line("USER _ _ _ :zeal");
    let expected = ":iris-server 001 zeal :Welcome to this server, zeal!";
    assert!(user_zeal.read_line().contains(expected));

    user_zeal.send_line("JOIN #c");
    let expected = ":zeal JOIN #c";
    assert!(user_zeal.read_line().contains(expected));

    user_james.send_line("NICK :james");
    user_james.send_line("USER _ _ _ :james");
    let expected = ":iris-server 001 james :Welcome to this server, james!";
    assert!(user_james.read_line().contains(expected));

    user_james.send_line("JOIN #c");
    let expected = ":james JOIN #c";
    assert!(user_james.read_line().contains(expected));
    assert!(user_zeal.read_line().contains(expected));

    user_zeal.send_line("PART #c");
    let expected = ":zeal PART #c";
    assert!(user_james.read_line().contains(expected));

    stop_server(server);
}

#[test]
fn test_PART_ERR_NEEDMOREPARAMS() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    let server = start_server(port);

    let mut user_zeal = Client::new(port);

    user_zeal.send_line("NICK :zeal");
    user_zeal.send_line("USER _ _ _ :zeal");
    let expected = ":iris-server 001 zeal :Welcome to this server, zeal!";
    assert!(user_zeal.read_line().contains(expected));

    user_zeal.send_line("JOIN #c");
    let expected = ":zeal JOIN #c";
    assert!(user_zeal.read_line().contains(expected));

    user_zeal.send_line("PART");
    let expected = ":iris-server :iris-server 461 :Not enough parameters";
    assert!(user_zeal.read_line().contains(expected));

    stop_server(server);
}

#[test]
fn test_PART_ERR_NOSUCHCHANNEL() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    let server = start_server(port);

    let mut user_zeal = Client::new(port);

    user_zeal.send_line("NICK :zeal");
    user_zeal.send_line("USER _ _ _ :zeal");
    let expected = ":iris-server 001 zeal :Welcome to this server, zeal!";
    assert!(user_zeal.read_line().contains(expected));

    user_zeal.send_line("JOIN #c");
    let expected = ":zeal JOIN #c";
    assert!(user_zeal.read_line().contains(expected));

    user_zeal.send_line("PART #a");
    let expected = ":iris-server :iris-server 403 :No such channel";
    assert!(user_zeal.read_line().contains(expected));

    stop_server(server);
}

// ##################################################
// # Testing PRIVMSG Commands
// ##################################################

#[test]
fn test_PRIVMSG_self() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    let server = start_server(port);

    let mut user_zeal = Client::new(port);

    user_zeal.send_line("NICK :zeal");
    user_zeal.send_line("USER _ _ _ :zeal");
    let expected = ":iris-server 001 zeal :Welcome to this server, zeal!";
    assert!(user_zeal.read_line().contains(expected));

    user_zeal.send_line("PRIVMSG zeal :You are the best!");
    let expected = ":zeal PRIVMSG zeal :You are the best!";
    assert!(user_zeal.read_line().contains(expected));

    stop_server(server);
}

#[test]
fn test_PRIVMSG_other_user() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    let server = start_server(port);

    let mut user_zeal = Client::new(port);
    let mut user_james = Client::new(port);

    user_zeal.send_line("NICK :zeal");
    user_zeal.send_line("USER _ _ _ :zeal");
    let expected = ":iris-server 001 zeal :Welcome to this server, zeal!";
    assert!(user_zeal.read_line().contains(expected));

    user_james.send_line("NICK :james");
    user_james.send_line("USER _ _ _ :james");
    let expected = ":iris-server 001 james :Welcome to this server, james!";
    assert!(user_james.read_line().contains(expected));

    user_zeal.send_line("PRIVMSG james :You are the best!");
    let expected = ":zeal PRIVMSG james :You are the best!";
    assert!(user_james.read_line().contains(expected));

    stop_server(server);
}

#[test]
fn test_PRIVMSG_channel() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    let server = start_server(port);

    let mut user_zeal = Client::new(port);
    let mut user_james = Client::new(port);

    user_zeal.send_line("NICK :zeal");
    user_zeal.send_line("USER _ _ _ :zeal");
    let expected = ":iris-server 001 zeal :Welcome to this server, zeal!";
    assert!(user_zeal.read_line().contains(expected));

    user_zeal.send_line("JOIN #c");
    let expected = ":zeal JOIN #c";
    assert!(user_zeal.read_line().contains(expected));

    user_james.send_line("NICK :james");
    user_james.send_line("USER _ _ _ :james");
    let expected = ":iris-server 001 james :Welcome to this server, james!";
    assert!(user_james.read_line().contains(expected));

    user_james.send_line("JOIN #c");
    let expected = ":james JOIN #c";
    assert!(user_james.read_line().contains(expected));
    assert!(user_zeal.read_line().contains(expected));

    user_zeal.send_line("PRIVMSG #c :Let's go!!!");
    let expected = ":zeal PRIVMSG #c :Let's go!!!";
    assert!(user_james.read_line().contains(expected));

    stop_server(server);
}

#[test]
fn test_PRIVMSG_ERR_NORECIPIENT() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    let server = start_server(port);

    let mut user_zeal = Client::new(port);

    user_zeal.send_line("NICK :zeal");
    user_zeal.send_line("USER _ _ _ :zeal");
    let expected = ":iris-server 001 zeal :Welcome to this server, zeal!";
    assert!(user_zeal.read_line().contains(expected));

    user_zeal.send_line("PRIVMSG");
    let expected = ":iris-server :iris-server 411 :No recipient given";
    assert!(user_zeal.read_line().contains(expected));

    stop_server(server);
}

#[test]
fn test_PRIVMSG_ERR_NOTEXTTOSEND() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    let server = start_server(port);

    let mut user_zeal = Client::new(port);

    user_zeal.send_line("NICK :zeal");
    user_zeal.send_line("USER _ _ _ :zeal");
    let expected = ":iris-server 001 zeal :Welcome to this server, zeal!";
    assert!(user_zeal.read_line().contains(expected));

    user_zeal.send_line("PRIVMSG zeal");
    let expected = ":iris-server :iris-server 412 :No text to send";
    assert!(user_zeal.read_line().contains(expected));

    stop_server(server);
}

#[test]
fn test_PRIVMSG_ERR_NOSUCHNICK() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    let server = start_server(port);

    let mut user_zeal = Client::new(port);

    user_zeal.send_line("NICK :zeal");
    user_zeal.send_line("USER _ _ _ :zeal");
    let expected = ":iris-server 001 zeal :Welcome to this server, zeal!";
    assert!(user_zeal.read_line().contains(expected));

    user_zeal.send_line("PRIVMSG james :Let's go!!!");
    let expected = ":iris-server :iris-server 401 :No such nick/channel";
    assert!(user_zeal.read_line().contains(expected));

    stop_server(server);
}

#[test]
fn test_PRIVMSG_ERR_NOSUCHCHANNEL() {
    increase_server_port();
    let port: u16 = unsafe { SERVER_PORT };

    let server = start_server(port);

    let mut user_zeal = Client::new(port);

    user_zeal.send_line("NICK :zeal");
    user_zeal.send_line("USER _ _ _ :zeal");
    let expected = ":iris-server 001 zeal :Welcome to this server, zeal!";
    assert!(user_zeal.read_line().contains(expected));

    user_zeal.send_line("PRIVMSG #c :Let's go!!!");
    let expected = ":iris-server :iris-server 403 :No such channel";
    assert!(user_zeal.read_line().contains(expected));

    stop_server(server);
}
