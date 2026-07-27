use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::os::unix::process::CommandExt;
use std::process::{exit, Command};

#[link(name = "crypt")]
unsafe extern "C" {
    fn crypt(key: *const i8, salt: *const i8) -> *mut i8;
}

unsafe extern "C" {
    fn getuid() -> u32;
    fn geteuid() -> u32;
    fn setuid(uid: u32) -> i32;
}

const CONFIG_PATH: &str = "/etc/mu.conf";

#[derive(Clone, Debug)]
enum Rule {
    Permit { nopass: bool },
    Deny,
}

fn read_config() -> HashMap<String, Rule> {
    let Ok(content) = fs::read_to_string(CONFIG_PATH) else {
        return HashMap::new();
    };
    let mut rules = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts.as_slice() {
            ["permit", user] => {
                rules.insert(user.to_string(), Rule::Permit { nopass: false });
            }
            ["permit", "nopass", user] => {
                rules.insert(user.to_string(), Rule::Permit { nopass: true });
            }
            ["deny", user] => {
                rules.insert(user.to_string(), Rule::Deny);
            }
            _ => {
                eprintln!("mu: invalid config line: {}", line);
            }
        }
    }
    rules
}

fn get_username(uid: u32) -> Option<String> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            if let Ok(u) = parts[2].parse::<u32>() {
                if u == uid {
                    return Some(parts[0].to_string());
                }
            }
        }
    }
    None
}

fn get_shadow_hash(user: &str) -> Option<String> {
    let shadow = fs::read_to_string("/etc/shadow").ok()?;
    for line in shadow.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 2 && parts[0] == user {
            let hash = parts[1];
            if hash.is_empty() || hash.starts_with('!') || hash.starts_with('*') {
                return None;
            }
            return Some(hash.to_string());
        }
    }
    None
}

fn verify_password(user: &str, password: &str) -> bool {
    let Some(hash) = get_shadow_hash(user) else {
        return false;
    };
    let Ok(key) = CString::new(password) else {
        return false;
    };
    let Ok(salt) = CString::new(hash.as_str()) else {
        return false;
    };
    let result = unsafe { crypt(key.as_ptr(), salt.as_ptr()) };
    if result.is_null() {
        return false;
    }
    let Ok(result_str) = (unsafe { std::ffi::CStr::from_ptr(result) }).to_str() else {
        return false;
    };
    result_str == hash
}

fn get_hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn die(msg: &str) -> ! {
    eprintln!("mu: {msg}");
    exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: mu <command> [args...]");
        exit(1);
    }

    let uid = unsafe { getuid() };
    let euid = unsafe { geteuid() };

    if euid != 0 {
        die("not running as root (setuid not configured?)");
    }

    if uid != 0 {
        let Some(username) = get_username(uid) else {
            die("could not determine username");
        };
        let hostname = get_hostname();
        let rules = read_config();

        match rules.get(&username) {
            Some(Rule::Deny) | None => {
                die(format!("{username} is not permitted to run commands as root").as_str());
            }
            Some(Rule::Permit { nopass: true }) => {}
            Some(Rule::Permit { nopass: false }) => {
                let prompt = format!(
                    "mu in ({username}@{hostname}) needs password for root command: \u{1F512} "
                );
                let password = rpassword::prompt_password(&prompt)
                    .unwrap_or_default();

                if !verify_password(&username, &password) {
                    die("authentication failed");
                }
            }
        }
    }

    unsafe {
        setuid(0);
    }

    let err = Command::new(&args[1]).args(&args[2..]).exec();
    die(format!("failed to exec '{}': {}", args[1], err).as_str());
}
