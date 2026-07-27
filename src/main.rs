use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
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

#[repr(C)]
struct tm {
    tm_sec: i32,
    tm_min: i32,
    tm_hour: i32,
    tm_mday: i32,
    tm_mon: i32,
    tm_year: i32,
    tm_wday: i32,
    tm_yday: i32,
    tm_isdst: i32,
}

unsafe extern "C" {
    fn localtime_r(timep: *const i64, result: *mut tm) -> *mut tm;
}

const CONFIG_PATH: &str = "/etc/mu.conf";
const AUDIT_LOG: &str = "/var/log/mu.log";
const FAIL_DIR: &str = "/var/log/mu/failures";

#[derive(Clone, Debug)]
enum Rule {
    Permit { nopass: bool },
    Deny,
}

struct Config {
    rules: HashMap<String, Rule>,
    maxfail: u32,
    blocktime: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rules: HashMap::new(),
            maxfail: 3,
            blocktime: 300,
        }
    }
}

fn read_config() -> Config {
    let Ok(content) = fs::read_to_string(CONFIG_PATH) else {
        return Config::default();
    };
    let mut cfg = Config::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts.as_slice() {
            ["permit", user] => {
                cfg.rules.insert(user.to_string(), Rule::Permit { nopass: false });
            }
            ["permit", "nopass", user] => {
                cfg.rules.insert(user.to_string(), Rule::Permit { nopass: true });
            }
            ["deny", user] => {
                cfg.rules.insert(user.to_string(), Rule::Deny);
            }
            ["maxfail", n] => {
                if let Ok(v) = n.parse() {
                    cfg.maxfail = v;
                }
            }
            ["blocktime", n] => {
                if let Ok(v) = n.parse() {
                    cfg.blocktime = v;
                }
            }
            _ => {
                eprintln!("mu: invalid config line: {}", line);
            }
        }
    }
    cfg
}

fn check_file_secure(path: &str) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    if meta.uid() != 0 || meta.gid() != 0 {
        return false;
    }
    if meta.mode() & 0o0022 != 0 {
        return false;
    }
    true
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

fn clean_env() {
    let safe: &[&str] = &[
        "HOME", "USER", "LOGNAME", "SHELL", "TERM",
        "DISPLAY", "LANG", "PATH", "TZ", "PWD",
    ];
    let keep: Vec<(String, String)> = safe
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
        .collect();
    for (k, _) in std::env::vars() {
        unsafe { std::env::remove_var(k) };
    }
    for (k, v) in keep {
        unsafe { std::env::set_var(&k, &v) };
    }
}

fn get_hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let mut t: tm = unsafe { std::mem::zeroed() };
    unsafe {
        localtime_r(&secs, &mut t);
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        t.tm_year + 1900,
        t.tm_mon + 1,
        t.tm_mday,
        t.tm_hour,
        t.tm_min,
        t.tm_sec
    )
}

fn ensure_log_dir() {
    fs::create_dir_all(FAIL_DIR).ok();
}

fn audit_log(user: &str, cmd: &str, success: bool) {
    let status = if success { "ACCEPT" } else { "FAILED" };
    let line = format!("{} {} {} '{}'\n", timestamp(), user, status, cmd);
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(AUDIT_LOG)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

fn check_blocked(user: &str, cfg: &Config) -> bool {
    let path = format!("{}/{}", FAIL_DIR, user);
    let Ok(content) = fs::read_to_string(&path) else {
        return false;
    };
    let parts: Vec<&str> = content.trim().split(',').collect();
    if parts.len() < 2 {
        return false;
    }
    let count: u32 = parts[0].parse().unwrap_or(0);
    let last_fail: u64 = parts[1].parse().unwrap_or(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if count >= cfg.maxfail && now - last_fail < cfg.blocktime {
        return true;
    }
    false
}

fn record_failure(user: &str, cfg: &Config) {
    let path = format!("{}/{}", FAIL_DIR, user);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (count, last_fail) = fs::read_to_string(&path)
        .ok()
        .and_then(|c| {
            let parts: Vec<&str> = c.trim().split(',').collect();
            if parts.len() >= 2 {
                Some((parts[0].parse::<u32>().unwrap_or(0), parts[1].parse::<u64>().unwrap_or(0)))
            } else {
                None
            }
        })
        .unwrap_or((0, 0));
    let count = if now - last_fail < cfg.blocktime { count + 1 } else { 1 };
    let _ = fs::write(&path, format!("{},{}\n", count, now));
}

fn clear_failures(user: &str) {
    let path = format!("{}/{}", FAIL_DIR, user);
    let _ = fs::remove_file(&path);
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

    if !check_file_secure("/etc/passwd") {
        die("/etc/passwd has insecure permissions");
    }

    if Path::new(CONFIG_PATH).exists() && !check_file_secure(CONFIG_PATH) {
        die("config file has insecure permissions");
    }

    let cmd = args[1..].join(" ");

    if uid != 0 {
        let Some(username) = get_username(uid) else {
            die("could not determine username");
        };
        let hostname = get_hostname();
        let cfg = read_config();

        match cfg.rules.get(&username) {
            Some(Rule::Deny) | None => {
                audit_log(&username, &cmd, false);
                die(format!("{username} is not permitted to run commands as root").as_str());
            }
            Some(Rule::Permit { nopass: true }) => {}
            Some(Rule::Permit { nopass: false }) => {
                ensure_log_dir();

                if check_blocked(&username, &cfg) {
                    audit_log(&username, &cmd, false);
                    die("too many failed attempts; try again later");
                }

                let prompt = format!(
                    "mu in ({username}@{hostname}) needs password for root command: \u{1F512} "
                );
                let password = rpassword::prompt_password(&prompt).unwrap_or_default();

                if !verify_password(&username, &password) {
                    record_failure(&username, &cfg);
                    audit_log(&username, &cmd, false);
                    die("authentication failed");
                }

                clear_failures(&username);
                audit_log(&username, &cmd, true);
            }
        }
    }

    clean_env();
    unsafe {
        setuid(0);
    }

    let err = Command::new(&args[1]).args(&args[2..]).exec();
    die(format!("failed to exec '{}': {}", args[1], err).as_str());
}
