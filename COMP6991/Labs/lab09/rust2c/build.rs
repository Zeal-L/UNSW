fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("Cargo provided");
    println!("cargo:rustc-link-search={dir}");
}
