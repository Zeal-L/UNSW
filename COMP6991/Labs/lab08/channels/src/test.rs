#[cfg(test)]
use std::process::Command; // Add methods on commands

#[test]
fn test() {
    // test that train_game works

    // compile the code
    let mut build = Command::new("6991")
        .args(["cargo", "build"])
        .spawn()
        .unwrap();
    let _result = build.wait().unwrap();

    // run the code
    let output = Command::new("6991")
        .args(["cargo", "run", "12345"])
        .output()
        .expect("failed to run binary");

    // test output contains correct num combs
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("There are 2880 potential combinations")
    );

    // assert that there are at least 59 lines of output
    // (one for each combination)
    assert!(String::from_utf8_lossy(&output.stdout).lines().count() >= 60);
}
