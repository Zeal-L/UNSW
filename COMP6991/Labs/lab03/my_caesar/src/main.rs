use std::io::{stdin, BufRead};
use std::env;
use std::char;

const DEFAULT_SHIFT: i32 = 5;

fn main() {
    let shift_by: i32 = env::args()
        .nth(1)
        .and_then(|arg| arg.parse().ok())
        .unwrap_or(DEFAULT_SHIFT);

    for line in stdin().lock().lines() {
        let shifted = shift(shift_by, line.expect("no input line"));

        println!("Shifted ascii by {shift_by} is: {shifted}");
    }
}


fn shift(shift_by: i32, line: String) -> String {
    // Caesar cipher, only works for le
    line.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let offset = if c.is_ascii_lowercase() {
                    b'a'
                } else {
                    b'A'
                } as i32;
                let shifted;
                if shift_by > 0 {
                    shifted = (c as i32 - offset + shift_by) % 26 + offset;
                } else {
                    shifted = (c as i32 - offset + shift_by + 26) % 26 + offset;
                }
                char::from_u32(shifted as u32).unwrap()
            } else {
                c
            }
        })
        .collect()
}
