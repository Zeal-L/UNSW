//! A simple web server
//! which serves some html at index.html
//! and replaces triple curly braces with the given variable
mod test;
use std::io::{Read, Write};

use std::net::{TcpListener, TcpStream};
// hint, hint
use std::sync::{Arc, Mutex};

struct State {
    counter: i32,
}

fn handle_client(mut stream: TcpStream, state: &mut State) {
    // setup buffer, and read from stream into buffer
    let mut buffer = [0; 1024];
    stream.read(&mut buffer).unwrap();

    // convert request payload to string
    let string = String::from_utf8_lossy(&buffer);

    // extract header
    let mut split = string.split("\r\n");
    let header = split.next().unwrap();

    if header == "POST /counter HTTP/1.1" {
        //TODO: increment the counter
        state.counter += 1;
    }

    let file = include_bytes!("../index.html");

    // TODO: replace triple brackets in file with the counter in state (array of bytes)
    //      - you should make sure your resulting content is still called file
    //      - or the below code will not work

    let temp = std::str::from_utf8(file)
        .unwrap()
        .replace("{{{ counter }}}", &state.counter.to_string());

    let file = temp.as_bytes();

    // DONT CHANGE ME
    let response = format!(
        "HTTP/1.1 200 OK\r\nContentType: text/html; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n",
        file.len()
    );

    // converts response to &[u8], and writes them to the stream
    stream.write_all(response.as_bytes()).unwrap();
    stream.write_all(file).unwrap();
    stream.flush().unwrap();
}

fn main() -> std::io::Result<()> {
    let port = std::env::args().nth(1).unwrap_or("8081".to_string());
    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))?;

    println!("Server running on port {}", port);
    // TODO: create new state, so that it can be safely
    //      shared between threads

    let state = Arc::new(Mutex::new(State { counter: -1 }));

    // accept connections and process them serially
    for stream in listener.incoming() {
        // TODO: spawn a thread for each connection
        // TODO: pass the state to the thread (and the handle_client fn)

        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            let mut state = state.lock().unwrap();
            handle_client(stream.unwrap(), &mut state);
        });
    }
    Ok(())
}
