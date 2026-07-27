# mu — minimal privilege escalation runner

Alternative to sudo/doas. Built in Rust, zero dependencies.

## Usage

```
mu <command> [args...]
```

## Install

### From source

```sh
git clone https://github.com/MulpinKR/mu.git
cd mu
cargo build --release
sudo chown root:root target/release/mu
sudo chmod u+s target/release/mu
sudo cp target/release/mu /usr/local/bin/mu
```

### Gentoo (GURU, yet its program is not in guru - waiting for guru maintainers to add program) 

```sh
eselect repository enable guru
emaint sync -r guru
emerge -a app-admin/mu
chown root:root /usr/bin/mu
chmod u+s /usr/bin/mu
```
