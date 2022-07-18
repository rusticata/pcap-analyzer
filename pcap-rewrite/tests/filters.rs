use assert_cmd::Command;
use std::env;

#[test]
fn test_filter1() {
    let mut cmd = Command::cargo_bin(env!("CARGO_PKG_NAME")).unwrap();
    let output = cmd.arg("--help").output().unwrap();
    println!("{:?}", output);
}
