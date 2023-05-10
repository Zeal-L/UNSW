fn main() {
    // try and get the first argument
    // using some iterator methods
    let arg = std::env::args()
        .skip(1)
        .next()
        .expect("should have one argument");

    // the compiler suggests to "borrow here"
    // but we haven't learnt how to borrow :(
    // we have a String type, and want to get a &str
    // Try find a function that can help us using
    // the docs https://doc.rust-lang.org/stable/std/string/struct.String.html
    let upp = uppercase(&arg);

    println!("arg = {}", arg);
    println!("upp = {}", upp);
}

fn uppercase(src: &str) -> String {
    let mut destination = String::new();

    for c in src.chars() {
        // this doesn't work either!!
        // what type does to_uppercase return?
        // what type does push expect?
        // Food for thought, what exactly is src.chars()?
        // TODO: read the docs!
        destination.push(c.to_uppercase().next().unwrap());
    }

    destination
}
