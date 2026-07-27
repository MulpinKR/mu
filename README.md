# mu — minimal privilege escalation runner

Alternative to sudo/doas. Built in Rust.

## Usage

```
mu <command> [args...]
```

## Config

`/etc/mu.conf` — per-user rules:

```
permit mulpin              # requires password
permit nopass alice        # no password
deny bob                   # explicitly denied
```

If a user has no rule, they are denied. Root is always allowed without a password.

## Install

### From source

```sh
git clone https://github.com/MulpinKR/mu.git
cd mu
cargo build --release
chown root:root target/release/mu
chmod u+s target/release/mu
cp target/release/mu /usr/local/bin/mu
```

### Gentoo (GURU, yet its program is not in guru - waiting for guru maintainers to add program) 

```sh
eselect repository enable guru
emaint sync -r guru
emerge -a app-admin/mu
chown root:root /usr/bin/mu
chmod u+s /usr/bin/mu
echo "permit $(whoami)" > /etc/mu.conf
```
