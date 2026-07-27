use std::os::unix::process::CommandExt;
use std::process::Command;

unsafe extern "C" {
    fn geteuid() -> u32;
    fn setuid(uid: u32) -> i32;
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("usage: mu <command> [args...]");
        std::process::exit(1);
    }

    let euid = unsafe { geteuid() };
    if euid != 0 {
        eprintln!("mu: not running as root (setuid not configured?)");
        std::process::exit(1);
    }

    unsafe {
        setuid(0);
    }

    let err = Command::new(&args[1]).args(&args[2..]).exec();

    eprintln!("mu: failed to exec '{}': {}", args[1], err);
    std::process::exit(1);
}
