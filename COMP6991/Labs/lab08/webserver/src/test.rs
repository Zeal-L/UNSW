#[cfg(test)]
use assert_cmd::prelude::*;
#[cfg(test)]
use std::process::Command; // Run programs // Add methods on commands

#[test]
fn test() {
    // connect to server
    // send GET request
    // check counter is 0
    // send POST request
    // check counter is 1
    // it should not be possible for these tests to fail, but to work in browser.

    let port = std::env::args().nth(2).unwrap_or("8081".to_string());

    let mut build = Command::new("6991")
        .args(["cargo", "build"])
        .spawn()
        .unwrap();

    let _result = build.wait().unwrap();

    if let Ok(mut child) = Command::cargo_bin("webserver")
        .expect("failed to find webserver binary")
        .spawn()
    {
        let result = std::panic::catch_unwind(|| {
            let url = format!("http://localhost:{}/", port);
            let resp = reqwest::blocking::get(url.clone())
                .expect("failed to get response")
                .text()
                .expect("failed to get text");
            assert!(!resp.contains("{{{ counter }}}"));
            assert!(resp.contains("<p>0</p>"));

            let client = reqwest::blocking::Client::new();
            client
                .post(format!("{url}counter"))
                .send()
                .expect("failed to send post request");

            let resp = reqwest::blocking::get(url.clone())
                .expect("failed to get response")
                .text()
                .expect("failed to get text");
            assert!(resp.contains("<p>1</p>"));
        });

        assert!(result.is_ok());

        child.kill().expect("failed to kill child");
    }

    Command::new("killall webserver");
}

