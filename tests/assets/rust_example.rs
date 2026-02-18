use std::process::Command;

fn main() {
    let _ = Command::new("ls");
    let _ = reqwest::get("https://example.com");
}
