# authd

A minimal privilege escalation daemon for Wayland, designed as a polkit replacement.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        GUI Flow                                  │
│  User App ──► authctl ──► authd ──► systemd-run ──► Target      │
│              (dialog)    (daemon)    (scoped)                    │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                        CLI Flow                                  │
│  Terminal ──► authsudo ──► exec() ──► Target                    │
│              (setuid)    (replaces process)                      │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                     polkit Compat Flow                           │
│  Legacy App ──► pkexec (shim) ──► authctl ──► authd ──► Target  │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### authd (daemon)
Root daemon listening on `/run/authd.sock`. Receives auth requests, checks policies, and spawns processes via `systemd-run --scope`.

### authctl (GUI client)
Wayland layer-shell dialog for authorization. Shows command to run, handles user confirmation. Uses iced with Ayu Dark theme.

### authsudo (CLI)
Setuid binary for terminal use. Checks policies, optionally prompts for password via PAM, then `exec()`s the target. Inherits stdin/stdout/signals naturally.

### pkexec (compatibility shim)
Drop-in replacement for polkit's pkexec. Translates pkexec invocations to authctl.

### authd-policy (library)
Shared policy engine used by both authd and authsudo.

### authd-protocol (library)
Shared types for daemon communication (AuthRequest, AuthResponse, PolicyRule).

## Policy Configuration

Policies are TOML files in `/etc/authd/policies.d/`.

### Policy Format

```toml
[[rules]]
target = "/usr/bin/gparted"
allow_groups = ["wheel"]
allow_users = ["admin"]
auth = "none"
cache_timeout = 300

[[rules]]
target = "*"                    # Wildcard matches any command
allow_groups = ["wheel"]
auth = "none"
```

### Auth Requirements

| Value      | Behavior                                      |
|------------|-----------------------------------------------|
| `none`     | Run immediately, no interaction               |
| `confirm`  | Show confirmation dialog (default)            |
| `password` | Require password authentication               |
| `deny`     | Always reject                                 |

### Matching Rules

1. Exact path match takes priority
2. Wildcard `*` matches any command
3. User must be in `allow_users` OR a member of `allow_groups`

## Installation

### Arch Linux

```bash
cd /path/to/authd
makepkg -si
```

### Manual

```bash
cargo build --release

# Daemon and client
install -Dm755 target/release/authd /usr/bin/authd
install -Dm755 target/release/authctl /usr/bin/authctl
install -Dm755 target/release/pkexec /usr/bin/authd-pkexec

# Setuid binary (important: mode 4755)
install -Dm4755 target/release/authsudo /usr/bin/authsudo

# Systemd service
install -Dm644 authd.service /usr/lib/systemd/system/authd.service

# PAM config
install -Dm644 etc/pam.d/authd /etc/pam.d/authd

# Create policy directory
install -dm755 /etc/authd/policies.d
```

## Usage

### Start the daemon

```bash
sudo systemctl start authd
```

### GUI authorization

```bash
authctl /usr/bin/gparted
```

### CLI authorization (sudo replacement)

```bash
authsudo ls -la /root
```

### polkit compatibility

```bash
# Symlink pkexec (after polkit updates, use the pacman hook)
ln -sf /usr/bin/authd-pkexec /usr/bin/pkexec
```

## Example Policies

### Allow wheel group without password

```toml
# /etc/authd/policies.d/wheel.toml
[[rules]]
target = "*"
allow_groups = ["wheel"]
auth = "none"
```

### Require password for sensitive tools

```toml
# /etc/authd/policies.d/sensitive.toml
[[rules]]
target = "/usr/bin/passwd"
allow_groups = ["wheel"]
auth = "password"

[[rules]]
target = "/usr/bin/visudo"
allow_users = ["admin"]
auth = "password"
```

### Deny specific commands

```toml
# /etc/authd/policies.d/deny.toml
[[rules]]
target = "/usr/bin/rm"
allow_groups = ["wheel"]
auth = "deny"
```

## Security Model

- **authd**: Runs as root, validates caller via Unix socket credentials (SO_PEERCRED)
- **authsudo**: Setuid root, gets real UID via `getuid()`, checks policy before escalation
- **Policies**: Only files in `/etc/authd/policies.d/` are loaded (root-owned)
- **PAM**: Password verification uses system PAM (`/etc/pam.d/authd`)

## Comparison with polkit

| Feature           | authd                  | polkit                    |
|-------------------|------------------------|---------------------------|
| Config format     | TOML                   | XML + JavaScript          |
| Complexity        | ~2000 lines Rust       | ~50000 lines C            |
| D-Bus dependency  | None                   | Required                  |
| GUI toolkit       | iced (Wayland-native)  | GTK                       |
| CLI support       | authsudo               | pkexec only               |

## License

MIT
