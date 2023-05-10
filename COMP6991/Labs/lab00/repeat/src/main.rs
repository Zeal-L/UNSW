fn main() {
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    print!("{line}")
}