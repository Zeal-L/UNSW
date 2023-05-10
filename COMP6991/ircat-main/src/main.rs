use bufstream::BufStream;
use rustyline::{error::ReadlineError, Editor};
use std::{
    error::Error,
    io::{BufRead, Write},
    net::{IpAddr, TcpStream},
    process,
    sync::mpsc::channel,
    thread,
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let address: IpAddr = {
        let arg = args.next().unwrap_or_else(|| "127.0.0.1".to_string());
        arg.parse()
            .unwrap_or_else(|_| panic!("invalid address: {arg}"))
    };

    let port: u16 = {
        let arg = args.next().unwrap_or_else(|| "6991".to_string());
        arg.parse()
            .unwrap_or_else(|_| panic!("invalid port: {arg}"))
    };

    let stream_read = TcpStream::connect((address, port))
        .unwrap_or_else(|_| panic!("failed to connect to {address}:{port}"));
    let mut stream_write = stream_read.try_clone().expect("failed to clone connection");

    let mut stream_read = BufStream::new(stream_read);

    let (send, recv) = channel::<String>();

    // network thread read
    {
        thread::spawn(move || {
            loop {
                let mut line = String::new();
                match stream_read.read_line(&mut line) {
                    Ok(0) => {
                        // EOF
                        eprintln!("server stopped responding");
                        process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("reader failed: {e:?}");
                        return;
                    }
                    Ok(_) => {
                        let line = line.trim();

                        println!("{line}");
                    }
                }
            }
        });
    }

    // network thread write
    {
        thread::spawn(move || {
            loop {
                match recv.recv() {
                    Ok(message) => {
                        if stream_write
                            .write_all(message.as_bytes())
                            .and_then(|_| stream_write.flush())
                            .is_err()
                        {
                            eprintln!("writer failed");
                        }
                    }
                    Err(_) => {
                        // hang up
                        return;
                    }
                }
            }
        });
    }

    // input thread
    {
        let mut rl = Editor::<()>::new()?;
        loop {
            let line = rl.readline("");
            match line {
                Ok(mut line) => {
                    rl.add_history_entry(&line);
                    line = line.trim().to_string();
                    line.push_str("\r\n");
                    send.send(line).unwrap();
                }
                Err(ReadlineError::Eof | ReadlineError::Interrupted) => {
                    process::exit(0);
                }
                Err(e) => {
                    eprintln!("failed to read further input");
                    eprintln!("Error: {e:?}");
                    return Err(Box::new(e));
                }
            }
        }
    }
}
