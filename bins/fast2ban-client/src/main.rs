fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = fast2ban_client::run_client(args);
    std::process::exit(code);
}
