fn main() {
    if let Err(err) = git_sshripped_cli::run() {
        eprintln!("Error: {err:#}");
        std::process::exit(1);
    }
}
