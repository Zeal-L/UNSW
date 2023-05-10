fn main() {
    let pattern_string = std::env::args()
        .nth(1)
        .expect("missing required command-line argument: <pattern>");

    let pattern = &pattern_string;

    loop {
        let mut buffer = String::new();
        std::io::stdin().read_line(&mut buffer).expect("failed to read from stdin");

        if buffer.contains(pattern) {
            println!("{}", buffer.trim());
            break;
        }
    }
}
