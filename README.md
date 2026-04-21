# DualServe — Enhanced HTTP & SMB File Transfer Server

A lightweight Python file transfer server for **authorized lab, internal admin, and pentest environments** that supports:

- HTTP file hosting and uploads
- Recursive file listing with a built-in browser
- Optional SMB share support via `impacket-smbserver`
- Real-time transfer progress bars
- MD5 hashing for integrity checks
- Transfer history logging
- Multi-interface IP detection

> **Use only on systems and networks you are explicitly authorized to test or administer.**

---

## Features

### HTTP
- Serve files over HTTP
- Upload files with `PUT` and `POST`
- Recursive file browser at `/files`
- JSON file index at `/list`
- Base64 download helper for small files
- Transfer log viewer at `/log`

### SMB
- Optional SMB file sharing using Impacket
- Anonymous or authenticated share access
- SMB2 enabled by default
- Console visibility into connections, share access, and file activity
- Can surface authentication-related events during client SMB access in authorized environments

### Quality of Life
- Recursive file discovery with directory grouping
- Colorized console output
- Real-time upload/download progress bars
- MD5 hashes for transfer verification
- Automatic network interface detection (`tun0`, `tap0`, `eth0`, etc.)
- Handy copy/paste command blocks for Windows and Linux

---

## Requirements

### Core
- Python 3

### Optional SMB Support
Install Impacket:

```bash
sudo apt install python3-impacket
