# kpassh

A terminal TUI for browsing KeePass (KDBX) databases and managing SSH keys via the SSH agent.

## Features

- Browse password entries by group with instant search
- Copy username, password, host, or URL to clipboard
- Detect and list SSH private keys (RSA, Ed25519, ECDSA) attached to KDBX entries
- Add/remove SSH keys to/from the running SSH agent — no passphrase prompt if stored in the entry's password field
- Reads the SSH key comment from the key file itself, preserving the original comment in the agent
- Internationalization: automatically uses English or Korean based on the OS locale (`LANGUAGE` / `LANG`)

## Installation

```bash
uv tool install .
```

### Requirements

- Python >= 3.9
- Dependencies: `pykeepass`, `textual`, `cryptography`, `bcrypt`, `appdirs`
- Clipboard: one of `wl-copy` (Wayland), `xclip`, or `xsel` (X11)

## Setup

Before the first run, place your KDBX database in the app data directory:

```bash
kpassh-db path              # show the expected database path
kpassh-db push              # copy database.kdbx from the current directory
kpassh-db push -i my.kdbx   # specify a custom filename
```

## Usage

### TUI viewer

```bash
kpassh                        # use the default database
kpassh /path/to/database.kdbx # specify a file
```

Enter the master password when prompted, then navigate the TUI.

### Key bindings

#### General

| Key | Action |
|-----|--------|
| `1` | Switch to Passwords tab |
| `2` | Switch to SSH Keys tab |
| `q` | Quit |

#### Passwords tab

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | Switch focus between Groups and Entries panels |
| `/` | Open search (group name, title, username, URL) |
| `Esc` | Clear search / go back |
| `u` | Copy username to clipboard |
| `p` | Copy password to clipboard |
| `h` | Copy host to clipboard (from `Host:` line in Notes, or URL) |
| `l` | Copy URL to clipboard |

#### SSH Keys tab

| Key | Action |
|-----|--------|
| `a` | Add selected key to SSH agent |
| `d` | Remove selected key from SSH agent |

The passphrase is automatically read from the entry's **Password** field when adding a key. A manual prompt appears only if the entry has no password or the password is incorrect.

### Database file management

The database is stored in the OS-specific user data directory.

| OS | Path |
|----|------|
| Linux | `~/.local/share/kpassh/database.kdbx` |
| macOS | `~/Library/Application Support/kpassh/database.kdbx` |
| Windows | `C:\Users\<user>\AppData\Local\kpassh\database.kdbx` |

```bash
kpassh-db path                    # print the database path
kpassh-db pull                    # copy from app data dir to current directory
kpassh-db pull -o backup.kdbx     # specify output filename
kpassh-db push                    # copy from current directory to app data dir
kpassh-db push -i edited.kdbx     # specify input filename
kpassh-db pull/push -f            # overwrite if destination already exists
```

## Project structure

```
kpassh/
  __init__.py
  main.py          # TUI viewer (Textual)
  ssh_agent.py     # SSH agent socket protocol, key parsing and fingerprinting
  db.py            # Database file management CLI
  i18n.py          # Internationalization (gettext, auto-detects OS locale)
  locale/
    ko/LC_MESSAGES/
      kpassh.po   # Korean translations source
      kpassh.mo   # compiled catalog
  database.kdbx    # bundled default database
```

## License

Internal use only.
