fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = fast2ban_regex::run(args);
    std::process::exit(code);
}
