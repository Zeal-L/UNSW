//! # A Encryption Crate!
//!
//! This crate provides an encryption function: [`caesar_shift`]
//!
//!
//! # Example
//!
//! ```
//! # use crate::doctor_who;
//! let lines = vec!["Hello, world!".to_string()];
//! assert_eq!(doctor_who::caesar_shift(Some(3), lines), ());
//! ```


/// This constant is the default shift value used by the [`caesar_shift`] function.
const DEFAULT_SHIFT: i32 = 5;
/// This constant is the ASCII value of the uppercase letter A.
const UPPERCASE_A: i32 = 65;
/// This constant is the ASCII value of the lowercase letter a.
const LOWERCASE_A: i32 = 97;
/// This constant is the number of letters in the alphabet.
const ALPHABET_SIZE: i32 = 26;


/// This function performs a Caesar shift on the input string(s),
/// where each letter in the string is shifted by a certain number
/// of positions down the alphabet.
/// If a shift value is provided as an argument, the function shifts
/// each letter in the input string(s) by that value. If no shift value
/// is provided, the function uses a default shift value of 5.
///
/// # Arguments:
///
/// * `shift_by`: [`Option<i32>`] - An optional integer value specifying the number of positions to shift each letter in the input string(s). If not provided, the default shift value of 5 is used.
/// * `lines`: [`Vec<String>`] - A vector of strings to be shifted using the Caesar cipher.
///
/// # Example
/// ```
/// # use crate::doctor_who;
/// let lines = vec!["Hello, world!".to_string()];
/// assert_eq!(doctor_who::caesar_shift(Some(13), lines), ());
/// ```
pub fn caesar_shift(shift_by: Option<i32>, lines: Vec<String>) {
    let shift_number = shift_by.unwrap_or(DEFAULT_SHIFT);
    lines.into_iter().for_each(|line| {
        println!(
            "Shifted ascii by {shift_number} is: {}",
            shift(shift_number, line)
        );
    });
}


/// It takes a line of text and a shift amount, and returns the line of text shifted by the shift amount
///
/// # Arguments:
///
/// * `shift_by`: The amount to shift by.
/// * `line`: The line to shift.
///
/// # Returns:
///
/// A string
fn shift(shift_by: i32, line: String) -> String {
    let mut result: Vec<char> = Vec::new();

    // turn shift_by into a positive number between 0 and 25
    let shift_by = shift_by % ALPHABET_SIZE + ALPHABET_SIZE;

    line.chars().for_each(|c| {
        let ascii = c as i32;

        if ('A'..='Z').contains(&c) {
            result.push(to_ascii(
                abs_modulo((ascii - UPPERCASE_A) + shift_by, ALPHABET_SIZE) + UPPERCASE_A,
            ));
        } else if ('a'..='z').contains(&c) {
            result.push(to_ascii(
                abs_modulo((ascii - LOWERCASE_A) + shift_by, ALPHABET_SIZE) + LOWERCASE_A,
            ));
        } else {
            result.push(c)
        }
    });

    result.iter().collect()
}

/// `abs_modulo` returns the absolute value of the remainder of `a` divided by `b`
///
/// # Arguments:
///
/// * `a`: The number to be divided.
/// * `b`: the number to divide by
///
/// # Returns:
///
/// The absolute value of the remainder of a divided by b.
fn abs_modulo(a: i32, b: i32) -> i32 {
    (a % b).abs()
}

/// It takes an integer and returns a character
///
/// # Arguments:
///
/// * `i`: i32 - The integer to convert to a character
///
/// # Returns:
///
/// A char
fn to_ascii(i: i32) -> char {
    char::from_u32(i as u32).unwrap()
}
