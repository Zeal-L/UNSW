fn main() {
    let s = String::from("hello, ");
    let t = String::from("world!");

    // currently, this function takes
    // OWNERSHIP of s and t
    // and so the compiler
    // complains: `use of moved value: s`
    // TODO: change the function call
    print_strings(&s, &t);

    // we try to use s and t here
    // but we can't because
    // they have been moved into the function
    // print_strings above
    println!("I want to use these strings! {}{}", s, t);
}

// TODO: change the function signature
fn print_strings(s: &String, t: &String) {
    println!("inside print_strings: {}{}", s, t);
}
