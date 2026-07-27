# mu — minimal privilege escalation runner

A lightweight alternative to sudo/doas with password auth, configurable rules, audit logging, and brute-force protection.

## Usage

```
mu <command> [args...]
mu fastfetch
mu emerge -av firefox
```

## Config: `/etc/mu.conf`

```
# User rules
permit mulpin              # requires password
permit nopass alice        # no password
deny bob                   # explicitly denied

# Security options
maxfail 3                  # lock after 3 failed attempts (default: 3)
blocktime 300              # unlock after 300 seconds (default: 300)
```

If a user has no rule, they are denied. Root is always allowed without a password.

## Security

- Environment sanitized before exec (drops LD_PRELOAD and other dangerous vars)
- Config and passwd file permissions verified (must be root-owned, not world-writable)
- Audit log at `/var/log/mu.log`
- Brute-force protection (configurable maxfail/blocktime)
- Uses system shadow passwords via `crypt(3)` for authentication

## Install

### From source

```sh
git clone https://github.com/MulpinKR/mu.git
cd mu
cargo build --release
chown root:root target/release/mu
chmod u+s target/release/mu
cp target/release/mu /usr/local/sbin/mu
echo "permit $(whoami)" > /etc/mu.conf
```

### Gentoo (GURU)

```sh
eselect repository enable guru
emaint sync -r guru
emerge -a app-admin/mu
chown root:root /usr/bin/mu
chmod u+s /usr/bin/mu
echo "permit $(whoami)" > /etc/mu.conf
```
