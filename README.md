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
Root daemon listening on `/run/authd.sock`. Receives auth requests, checks policies, and spawns processes via `systemd-run --scope`. Confirmation requests run in a separate `session-dialog` child process. If the client disconnects before the decision, authd cancels and reaps that child without writing a response to the closed socket.

### authctl (GUI client)
Wayland layer-shell dialog for authorization. Shows command to run, handles user confirmation. Uses iced with Ayu Dark theme.

### authsudo (CLI)
Setuid binary for terminal use. Checks policies, optionally prompts for password via PAM, then `exec()`s the target. Inherits stdin/stdout/signals naturally.

### pkexec (compatibility shim)
Drop-in replacement for polkit's pkexec. Translates pkexec invocations to authctl.

### authd-polkit-agent (polkit authentication agent)
Runs in the user's graphical session and registers with the real `polkitd` as
the session's authentication agent (over D-Bus/zbus). When polkit needs the user
to authenticate (e.g. `systemctl` → `org.freedesktop.systemd1.manage-units`), it
forwards the request to the root `authd` daemon, which shows its confirm dialog
and — on approval — asserts `AuthenticationAgentResponse2` to polkitd. This is an
allow/forbid model: **no password**, just authd's existing confirmation. polkitd
trusts the response because authd is root (the same trust model as polkit's own
setuid `polkit-agent-helper-1`). Enable the shipped user unit with
`systemctl --user enable --now authd-polkit-agent`.

### authd-policy (library)
Shared policy engine used by both authd and authsudo.

### authd-protocol (library)
Shared types for daemon communication (AuthRequest, AuthResponse, ConfirmSessionRequest, ConfirmSessionResponse, PolicyRule).

## Secrets Broker confirmation

The Secrets Broker may request a confirmation for a specific Pi session by sending a `ConfirmSessionRequest` to authd. Only a caller whose socket executable is exactly `/usr/bin/secrets-broker` is accepted for this flow.

Authd independently validates the claimed Pi process before showing the dialog:

- PID still exists and its `/proc/<pid>/stat` start time matches the request
- `/proc/<pid>/exe` is `pi` or `pi-dev`
- process UID matches the requested target UID
- `WAYLAND_DISPLAY` and `XDG_RUNTIME_DIR` are present in the Pi process environment
- the runtime directory is owned by the target UID
- the process start time still matches after validation

The dialog is launched as the validated target UID/GID with the validated session environment. The response is `Confirmed`, `Denied`, or `Error`. Disconnecting the broker while confirmation is pending cancels and reaps the dialog process without sending a response.

## Operational behavior

### Confirmation cancellation

Authd monitors the caller connection while a confirmation is pending. A caller disconnect cancels the pending confirmation, terminates and reaps the `session-dialog` child, and skips the response write. This prevents stale dialogs from surviving a timed-out client request.

### Request-correlated diagnostics

Authd assigns each request a `request_id` and logs monotonic `elapsed_ms` values for connection acceptance, request decoding, operation start/completion, dialog spawn/completion, response writes, and caller disconnects. The child `session-dialog` process receives the same ID and logs its own startup, config decoding, application startup, and UI return stages. Inspect system logs with:

```bash
journalctl -u authd
```

### Deployment

Use the repository deployment script:

```bash
./deploy.sh
```

It builds with `--locked`, installs the authd binaries and service files, reloads/restarts the system `authd.service`, and reloads/restarts the current user's `authd-polkit-agent.service`. The separate `session-dialog` project must already have installed `/usr/bin/session-dialog`; authd launches that binary for confirmation dialogs.

## Policy Configuration

Policies are TOML files in `/etc/authd/policies.d/`.

### Policy Format

```toml
[[rules]]
target = "/usr/bin/gparted"
allow_groups = ["wheel"]
allow_users = ["admin"]
allow_callers = ["/usr/bin/claude"]   # Trusted callers bypass auth
auth = "confirm"
cache_timeout = 300

[[rules]]
target = "*"                    # Wildcard matches any command
allow_groups = ["wheel"]
auth = "none"
```

### Auth Requirements

| Value      | GUI (authctl)                    | CLI (authsudo)                   |
|------------|----------------------------------|----------------------------------|
| `none`     | Run immediately                  | Run immediately                  |
| `confirm`  | Show dialog (default)            | Run immediately (no TTY dialog)  |
| `password` | Error: use authsudo              | Prompt for password via PAM      |
| `deny`     | Reject                           | Reject                           |

**Note:** Password authentication is only supported via `authsudo` in a terminal. The GUI flow intentionally doesn't support password entry.

### Matching Rules

1. Exact path match takes priority
2. Wildcard `*` matches any command
3. User must be in `allow_users` OR a member of `allow_groups`

### Trusted Callers

The `allow_callers` field works like `allow_users` and `allow_groups` - it authorizes which binaries can run the target. The caller is identified via `/proc/<pid>/exe`.

To allow Claude to run commands without confirmation, use `allow_callers` with `auth = "none"`.

## Installation

### Arch Linux

```bash
cd /path/to/authd
makepkg -si
```

### Manual

The canonical deployment path is `./deploy.sh`; it also restarts both authd services. For manual installation:

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

### Allow Claude Code to run commands without prompts

```toml
# /etc/authd/policies.d/claude.toml
[[rules]]
target = "*"
allow_callers = ["/usr/bin/claude"]
auth = "none"
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
| D-Bus usage       | agent only (zbus)      | full Authority + agents   |
| GUI toolkit       | iced (Wayland-native)  | GTK                       |
| CLI support       | authsudo               | pkexec only               |

> **D-Bus note:** authd's own daemon protocol is D-Bus-free (msgpack over a Unix
> socket). The optional `authd-polkit-agent` does use D-Bus (zbus): it registers
> with the real `polkitd` as the session's authentication agent so that bare
> `systemctl`/`NetworkManager`/etc. prompts route through authd's confirm dialog
> instead of polkit-gnome. See "polkit authentication agent" below.

## License

MIT
