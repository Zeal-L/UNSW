use require_lifetimes::require_lifetimes;
// ONLY MODIFY LINES 11 AND 27
/// DO NOT MODIFY COMMENT
/// ```rust
/// use annotate_lifetimes::identity;
///
/// let x = 3;
/// assert_eq!(identity(&x), &x);
/// ````
#[require_lifetimes(!)]
pub fn identity<'a>(number: &'a i32) -> &'a i32 {
    number
}

/// DO NOT MODIFY COMMENT
/// ```rust
/// use annotate_lifetimes::split;
/// let text = String::from("this is a test");
/// let splitted = {
///     let delimiter = String::from(" ");
///     split(&text, &delimiter)
///     // delimiter is dropped here.
/// };
/// assert_eq!(splitted, vec!["this", "is", "a", "test"]);
/// ```
#[require_lifetimes(!)]
pub fn split<'a, 'b>(text: &'a str, delimiter: &'b str) -> Vec<&'a str> {
    let mut last_split = 0;
    let mut matches: Vec<&str> = vec![];
    for i in 0..text.len() {
        if i < last_split {
            continue;
        }
        if text[i..].starts_with(delimiter) {
            matches.push(&text[last_split..i]);
            last_split = i + delimiter.len();
        }
    }
    if last_split < text.len() {
        matches.push(&text[last_split..]);
    }

    matches
}
