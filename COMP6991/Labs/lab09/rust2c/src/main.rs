use std::{fmt::Debug, str::FromStr};

use libc::{c_char, c_double, c_int};

const USAGE_STR: &str = "Usage: cargo run -- <x> <y> <z>";

#[link(name = "secretc")]
extern "C" {
    // TODO: Define the external C function
    // "secret_c_calculation"
    fn secret_c_calculation(x: c_int, y: c_double, z: c_char) -> c_int;
}

fn next_arg<T: FromStr>(args: &mut impl Iterator<Item = String>, message: &str) -> T
where
    <T as FromStr>::Err: Debug,
{
    args.next().expect(USAGE_STR).parse().expect(message)
}

fn main() {
    let mut args = std::env::args().skip(1);

    let x: i32 = next_arg(&mut args, "x must be i32");
    let y: f64 = next_arg(&mut args, "y must be f64");
    let z: char = next_arg(&mut args, "z must be char");

    // TODO: Call the external C function "secret_c_calculation"
    // with parameters x, y, z
    let secret_value = unsafe { secret_c_calculation(x, y, z as i8) };

    println!("The secret value is {secret_value}");
}
