#!/usr/bin/env python3
# =============================================================================
# DualServe — HTTP & SMB File Transfer Server
# =============================================================================
# Cross-distro version of 1337codes' OSCP-HTTP-SMB-File-Transfer-Server.
#
# Improvements over upstream:
#   - No hardcoded paths (uses $HOME or --dir)
#   - Auto-detects impacket-smbserver (Kali) vs smbserver.py (Arch/BlackArch)
#   - Interactive network interface picker (tun0 default for HTB/THM/OSCP)
#   - Cleaner argparse with helpful error messages
#   - Defensive shutdown of SMB subprocess on exit
#
# Use only on systems and networks you are explicitly authorized to test.
# =============================================================================

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import deque
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler

# cgi was removed in Python 3.13. Try to import; fall back to email parser.
try:
    import cgi
    HAS_CGI = True
except ImportError:
    HAS_CGI = False
    import email
    from io import BytesIO

# =============================================================================
# Defaults (override via CLI args or env vars)
# =============================================================================
DEFAULT_HTTP_PORT = 80
DEFAULT_SMB_PORT = 445
DEFAULT_SMB_SHARE = "evil"
DEFAULT_IFACE = "tun0"  # HTB/THM/OSCP default
CHUNK_SIZE = 64 * 1024

# Default download dir: $TOOLS_DIR/http-smb-server if set, else ~/Desktop/tools/http-smb-server,
# else current working dir. Always overridable with --dir.
def _default_download_dir():
    tools_dir = os.environ.get("TOOLS_DIR")
    if tools_dir:
        candidate = os.path.join(tools_dir, "http-smb-server")
        if os.path.isdir(candidate):
            return candidate
    home_default = os.path.expanduser("~/Desktop/tools/http-smb-server")
    if os.path.isdir(home_default):
        return home_default
    return os.getcwd()

# =============================================================================
# Globals
# =============================================================================
transfer_log = []
smb_proc = None  # Holds smb subprocess for cleanup on exit


# =============================================================================
# Color helpers
# =============================================================================
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    WHITE = "\033[97m"
    UNDERLINE = "\033[4m"


def timestamp():
    return datetime.now().strftime("%H:%M:%S")


def info(msg):
    print(f"{C.GRAY}[{timestamp()}]{C.RESET} {C.BLUE}[INFO]{C.RESET} {msg}")


def ok(msg):
    print(f"{C.GRAY}[{timestamp()}]{C.RESET} {C.GREEN}[OK]{C.RESET} {msg}")


def warn(msg):
    print(f"{C.GRAY}[{timestamp()}]{C.RESET} {C.YELLOW}[WARN]{C.RESET} {msg}")


def err(msg):
    print(f"{C.GRAY}[{timestamp()}]{C.RESET} {C.RED}[ERR]{C.RESET} {msg}", file=sys.stderr)


# =============================================================================
# Network interface detection & picker
# =============================================================================

def get_interfaces():
    """Return list of (name, ipv4) tuples for non-loopback interfaces."""
    interfaces = []
    try:
        out = subprocess.check_output(
            ["ip", "-o", "-4", "addr", "show"], stderr=subprocess.DEVNULL
        ).decode()
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            iface = parts[1]
            if iface == "lo":
                continue
            ip = parts[3].split("/")[0]
            interfaces.append((iface, ip))
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback for systems without `ip` command
        try:
            out = subprocess.check_output(["ifconfig"], stderr=subprocess.DEVNULL).decode()
            current_iface = None
            for line in out.splitlines():
                if line and not line.startswith((" ", "\t")):
                    current_iface = line.split(":")[0].split()[0]
                elif "inet " in line and current_iface and current_iface != "lo":
                    m = re.search(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        interfaces.append((current_iface, m.group(1)))
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
    return interfaces


def pick_interface(force_iface=None, default_iface=None, prompt=True):
    """
    Returns (iface_name, iface_ip).
    - If force_iface given and exists, returns it without prompting.
    - Otherwise shows menu with default_iface (or DEFAULT_IFACE) preselected.
    """
    interfaces = get_interfaces()
    if not interfaces:
        err("No network interfaces with IPv4 found")
        sys.exit(1)

    default_iface = default_iface or os.environ.get("TOOLS_DEFAULT_IFACE") or DEFAULT_IFACE
    force_iface = force_iface or os.environ.get("TOOLS_FORCE_IFACE")

    # Forced interface
    if force_iface:
        for name, ip in interfaces:
            if name == force_iface:
                info(f"Forced interface: {name} ({ip})")
                return name, ip
        warn(f"Forced interface '{force_iface}' not found, falling back to picker")

    # If picker disabled (non-interactive), use default or first
    if not prompt or not sys.stdin.isatty():
        for name, ip in interfaces:
            if name == default_iface:
                info(f"Using default interface (non-interactive): {name} ({ip})")
                return name, ip
        name, ip = interfaces[0]
        info(f"Using first interface (non-interactive): {name} ({ip})")
        return name, ip

    # Find default index
    default_idx = 0
    for i, (name, _) in enumerate(interfaces):
        if name == default_iface:
            default_idx = i
            break

    # Show picker
    print(f"\n{C.BOLD}{C.CYAN}==[ Pick interface ]=={C.RESET}")
    for i, (name, ip) in enumerate(interfaces):
        marker = f" {C.GREEN}*{C.RESET}" if i == default_idx else "  "
        print(f"  {marker} {C.BOLD}{i+1}{C.RESET}) {name:<12} {C.GRAY}{ip}{C.RESET}")
    print(f"     {C.GRAY}(* = default){C.RESET}")

    try:
        choice = input(f"Choice [Enter for {C.GREEN}{interfaces[default_idx][0]}{C.RESET}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return interfaces[default_idx]

    if not choice:
        return interfaces[default_idx]

    # Numeric choice
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(interfaces):
            return interfaces[idx]
        warn("Out of range, using default")
        return interfaces[default_idx]

    # Name choice
    for name, ip in interfaces:
        if name == choice:
            return name, ip
    warn(f"Interface '{choice}' not found, using default")
    return interfaces[default_idx]


# =============================================================================
# File helpers
# =============================================================================

def get_md5(filepath):
    h = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except (OSError, IOError):
        return "N/A"
    return h.hexdigest()


def get_file_color(filename):
    ext = os.path.splitext(filename)[1].lower()
    return {
        ".exe": C.RED, ".dll": C.RED, ".bat": C.RED, ".elf": C.RED, ".bin": C.RED,
        ".ps1": C.BLUE, ".psm1": C.BLUE,
        ".sh": C.GREEN, ".py": C.YELLOW,
        ".rb": C.MAGENTA, ".pl": C.MAGENTA,
        ".txt": C.WHITE, ".md": C.WHITE,
        ".conf": C.CYAN, ".cfg": C.CYAN, ".xml": C.CYAN, ".json": C.CYAN,
        ".zip": C.YELLOW, ".tar": C.YELLOW, ".gz": C.YELLOW, ".7z": C.YELLOW,
    }.get(ext, C.RESET)


def get_all_files_recursive(directory, max_depth=2, max_files=500):
    all_files = []

    def scan_dir(path, current_depth=0):
        if current_depth > max_depth or len(all_files) >= max_files:
            return
        try:
            for item in sorted(os.listdir(path)):
                if item.startswith("."):
                    continue
                if len(all_files) >= max_files:
                    return
                full_path = os.path.join(path, item)
                rel_path = os.path.relpath(full_path, directory)
                if os.path.isfile(full_path):
                    all_files.append((rel_path, os.path.getsize(full_path), current_depth))
                elif os.path.isdir(full_path):
                    scan_dir(full_path, current_depth + 1)
        except (PermissionError, OSError):
            pass

    scan_dir(directory)
    return all_files


def format_size(size):
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"


def format_speed(speed):
    for unit in ["B/s", "KB/s", "MB/s", "GB/s"]:
        if speed < 1024:
            return f"{speed:.1f}{unit}"
        speed /= 1024
    return f"{speed:.1f}TB/s"


def print_files_table(files):
    if not files:
        print(f"{C.WHITE}No files found in download directory{C.RESET}")
        return
    top_level = [(p, s) for p, s, d in files if d == 0]
    directories = {}
    for rel, size, depth in files:
        if depth > 0:
            top = rel.split("/")[0]
            directories.setdefault(top, {"count": 0, "size": 0})
            directories[top]["count"] += 1
            directories[top]["size"] += size

    print(f"{C.WHITE}Available files: {len(files)} ({len(top_level)} root, {len(directories)} dirs){C.RESET}")
    if directories:
        print(f"\n{C.YELLOW}DIRECTORIES:{C.RESET}")
        for d in sorted(directories):
            print(f"  {C.CYAN}{d}/{C.RESET} {C.GRAY}({directories[d]['count']} files, {format_size(directories[d]['size'])}){C.RESET}")
    if top_level:
        print(f"\n{C.YELLOW}TOP-LEVEL FILES:{C.RESET}")
        for name, size in top_level[:30]:
            print(f"  {get_file_color(name)}{name:<55}{C.RESET} {C.GRAY}{format_size(size)}{C.RESET}")
        if len(top_level) > 30:
            print(f"  {C.GRAY}... and {len(top_level) - 30} more{C.RESET}")


# =============================================================================
# HTML head/foot
# =============================================================================

def get_html_head(title):
    return f"""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
body {{ font-family: 'Consolas', 'Monaco', monospace; background: #1a1a2e; color: #eee; padding: 20px; margin: 0; }}
h1, h2 {{ color: #00ff88; margin-top: 0; }}
h3 {{ color: #ccc; margin: 0 0 10px 0; font-size: 14px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #333; }}
tr:hover {{ background: #16213e; }}
a {{ color: #00d4ff; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.size {{ color: #888; }}
pre {{ background: #0f0f23; padding: 12px; border-radius: 5px; overflow-x: auto; word-wrap: break-word; white-space: pre-wrap; margin: 0; font-size: 13px; }}
.code-block {{ position: relative; }}
.copy-btn {{
    position: absolute; top: 8px; right: 8px;
    background: #00d4ff; color: #000; border: none;
    padding: 5px 10px; border-radius: 3px; cursor: pointer;
    font-family: inherit; font-size: 11px; font-weight: bold;
}}
.copy-btn:hover {{ background: #00ff88; }}
.download {{ color: #00d4ff; }}
.upload {{ color: #00ff88; }}
.nav {{ margin-bottom: 20px; padding: 10px; background: #0f0f23; border-radius: 5px; }}
.nav a {{ margin-right: 20px; }}
.two-col {{ display: flex; gap: 20px; margin: 20px 0; }}
.two-col > div {{ flex: 1; min-width: 0; }}
.section {{ margin: 20px 0; }}
.file-cmds {{ font-size: 11px; color: #888; }}
.file-cmds code {{ background: #0f0f23; padding: 2px 6px; border-radius: 3px; color: #00d4ff; }}
</style>
</head><body>
<div class="nav">
<a href="/files">Files</a>
<a href="/log">Log</a>
</div>
"""


HTML_FOOT = """
<script>
function copyCmd(btn, id) {
    var el = document.getElementById(id);
    var text = el.innerText || el.textContent;
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function() {
            btn.innerText = 'Copied!';
            btn.style.background = '#00ff88';
            setTimeout(function() { btn.innerText = 'Copy'; btn.style.background = '#00d4ff'; }, 1500);
        });
    } else {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        try {
            document.execCommand('copy');
            btn.innerText = 'Copied!';
            btn.style.background = '#00ff88';
            setTimeout(function() { btn.innerText = 'Copy'; btn.style.background = '#00d4ff'; }, 1500);
        } catch(e) {}
        document.body.removeChild(ta);
    }
}
</script>
</body></html>"""


# =============================================================================
# Progress bar
# =============================================================================

class ProgressBar:
    def __init__(self, filename, total_size, direction="DOWN"):
        self.filename = filename
        self.total_size = total_size
        self.transferred = 0
        self.direction = direction
        self.start_time = time.time()
        self.last_update = 0

    def update(self, chunk_size):
        self.transferred += chunk_size
        now = time.time()
        if now - self.last_update < 0.1 and self.transferred < self.total_size:
            return
        self.last_update = now

        percent = (self.transferred / self.total_size) * 100 if self.total_size > 0 else 0
        elapsed = now - self.start_time
        speed = self.transferred / elapsed if elapsed > 0 else 0

        if speed > 0 and self.total_size > 0:
            eta = (self.total_size - self.transferred) / speed
            eta_str = f"{eta:.0f}s" if eta < 60 else f"{eta/60:.1f}m"
        else:
            eta_str = "---"

        bar_width = 25
        filled = int(bar_width * percent / 100)
        bar = "█" * filled + "░" * (bar_width - filled)
        arrow = f"{C.CYAN}↓{C.RESET}" if self.direction == "DOWN" else f"{C.GREEN}↑{C.RESET}"

        line = (
            f"\r{arrow} {C.YELLOW}[{bar}]{C.RESET} {percent:5.1f}% | "
            f"{format_size(self.transferred)}/{format_size(self.total_size)} | "
            f"{format_speed(speed)} | ETA: {eta_str} "
        )
        sys.stdout.write(line)
        sys.stdout.flush()

    def finish(self):
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()


# =============================================================================
# HTTP Handler
# =============================================================================

class DualHandler(SimpleHTTPRequestHandler):
    upload_dir = None
    download_dir = None
    server_ip = None
    server_port = None

    def translate_path(self, path):
        # Force translation relative to download_dir
        path = path.split("?", 1)[0].split("#", 1)[0]
        path = urllib.parse.unquote(path)
        # Sanitize
        words = [w for w in path.split("/") if w and w != ".." and w != "."]
        result = self.download_dir
        for w in words:
            result = os.path.join(result, w)
        return result

    def do_GET(self):
        if self.path in ("/list", "/list/"):
            self.handle_list_json()
            return
        if self.path in ("/files", "/files/"):
            self.handle_file_browser()
            return
        if self.path.startswith("/b64/"):
            self.handle_base64_download()
            return
        if self.path in ("/log", "/log/"):
            self.handle_log()
            return

        path = self.translate_path(self.path)
        try:
            filename = os.path.relpath(path, self.download_dir)
        except Exception:
            filename = os.path.basename(self.path) or "/"

        ts = timestamp()
        print(f"{C.GRAY}[{ts}]{C.RESET} {C.YELLOW}[GET]{C.RESET} {filename} <- {self.client_address[0]}")

        if os.path.isfile(path):
            self.send_file_with_progress(path, filename)
        else:
            self.send_error(404, "File not found")
            print(f"{C.GRAY}[{ts}]{C.RESET} {C.RED}[FAIL]{C.RESET} {filename} not found")

    def handle_list_json(self):
        files = []
        for rel_path, size, depth in get_all_files_recursive(self.download_dir):
            filepath = os.path.join(self.download_dir, rel_path)
            files.append({
                "name": rel_path,
                "size": size,
                "depth": depth,
                "md5": get_md5(filepath),
            })
        body = json.dumps(files, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_file_browser(self):
        files = get_all_files_recursive(self.download_dir)
        groups = {"_root": []}
        for rel, size, depth in files:
            if depth == 0:
                groups["_root"].append((rel, size, depth))
            else:
                top = rel.split("/")[0]
                groups.setdefault(top, []).append((rel, size, depth))

        html = get_html_head("File Server")
        html += f"""<h1>File Server</h1>
<p>IP: {self.server_ip} | Port: {self.server_port} | Files: {len(files)}</p>
<input type="text" id="searchBox" placeholder="Search files..."
  style="width:100%;padding:10px;margin:10px 0;background:#0f0f23;color:#eee;border:1px solid #333;border-radius:5px;font-family:inherit;">
<div id="fileList">
"""

        if groups["_root"]:
            html += f"<h3>Root Files ({len(groups['_root'])})</h3>"
            html += '<table class="file-table"><tr><th>File</th><th>Size</th><th>Command</th></tr>'
            for rel, size, _ in groups["_root"]:
                url = urllib.parse.quote(rel)
                html += f'<tr class="file-row" data-name="{rel.lower()}">'
                html += f'<td><a href="/{url}">{rel}</a></td>'
                html += f'<td class="size">{format_size(size)}</td>'
                html += f'<td class="file-cmds"><code>download {rel}</code></td></tr>'
            html += "</table>"

        for d in sorted(k for k in groups if k != "_root"):
            dfiles = groups[d]
            total = sum(s for _, s, _ in dfiles)
            html += f'<h3>{d}/ ({len(dfiles)} files, {format_size(total)})</h3>'
            html += '<table class="file-table"><tr><th>Path</th><th>Size</th><th>Command</th></tr>'
            for rel, size, _ in dfiles:
                url = urllib.parse.quote(rel)
                html += f'<tr class="file-row" data-name="{rel.lower()}">'
                html += f'<td><a href="/{url}">{rel}</a></td>'
                html += f'<td class="size">{format_size(size)}</td>'
                html += f'<td class="file-cmds"><code>download {rel}</code></td></tr>'
            html += "</table>"

        html += """</div>
<script>
document.getElementById('searchBox').addEventListener('input', function(e) {
    var search = e.target.value.toLowerCase();
    document.querySelectorAll('.file-row').forEach(function(row) {
        row.style.display = row.getAttribute('data-name').includes(search) ? '' : 'none';
    });
});
</script>"""
        html += HTML_FOOT
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_base64_download(self):
        rel = urllib.parse.unquote(self.path[5:])
        filepath = os.path.join(self.download_dir, rel)
        if not os.path.isfile(filepath):
            self.send_error(404, "File not found")
            return
        size = os.path.getsize(filepath)
        if size > 1024 * 1024:
            self.send_error(413, "File too large for base64 (max 1MB)")
            return
        with open(filepath, "rb") as f:
            encoded = base64.b64encode(f.read()).decode()
        filename = os.path.basename(rel)
        md5 = get_md5(filepath)

        linux = f"echo '{encoded}' | base64 -d > {filename}"
        ps = f'[IO.File]::WriteAllBytes("$pwd\\{filename}", [Convert]::FromBase64String("{encoded}"))'

        html = get_html_head(f"Base64: {filename}")
        html += f"""<h2>Base64: {rel}</h2>
<p>Size: {format_size(size)} | Encoded: {len(encoded)} chars | MD5: {md5}</p>
<div class="two-col">
<div><h3>Linux</h3><div class="code-block"><button class="copy-btn" onclick="copyCmd(this,'lc')">Copy</button>
<pre id="lc">{linux}</pre></div></div>
<div><h3>PowerShell</h3><div class="code-block"><button class="copy-btn" onclick="copyCmd(this,'pc')">Copy</button>
<pre id="pc">{ps}</pre></div></div>
</div>
<div class="section"><h3>Raw Base64</h3>
<div class="code-block"><button class="copy-btn" onclick="copyCmd(this,'rb')">Copy</button>
<pre id="rb">{encoded}</pre></div></div>
"""
        html += HTML_FOOT
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_log(self):
        html = get_html_head("Transfer Log")
        html += "<h1>Transfer Log</h1><table>"
        html += "<tr><th>Time</th><th>Type</th><th>File</th><th>Size</th><th>Client</th><th>MD5</th></tr>"
        for entry in reversed(transfer_log[-50:]):
            cls = "download" if entry["type"] == "DOWN" else "upload"
            html += f"<tr><td>{entry['time']}</td><td class='{cls}'>{entry['type']}</td>"
            html += f"<td>{entry['file']}</td><td>{entry['size']}</td>"
            html += f"<td>{entry['client']}</td><td>{entry.get('md5','N/A')[:16]}...</td></tr>"
        if not transfer_log:
            html += '<tr><td colspan="6" style="text-align:center;color:#666;">No transfers yet</td></tr>'
        html += "</table>" + HTML_FOOT
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_file_with_progress(self, path, filename):
        try:
            size = os.path.getsize(path)
            md5 = get_md5(path)
            self.send_response(200)
            self.send_header("Content-Type", self.guess_type(path))
            self.send_header("Content-Length", str(size))
            self.send_header("X-MD5", md5)
            self.end_headers()
            pb = ProgressBar(filename, size, "DOWN")
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    try:
                        self.wfile.write(chunk)
                        pb.update(len(chunk))
                    except (BrokenPipeError, ConnectionResetError):
                        pb.finish()
                        print(f"{C.GRAY}[{timestamp()}]{C.RESET} {C.RED}[FAIL]{C.RESET} {filename} - connection lost")
                        return
            pb.finish()
            elapsed = time.time() - pb.start_time
            avg = size / elapsed if elapsed > 0 else 0
            ts = timestamp()
            color = get_file_color(filename)
            print(f"{C.GRAY}[{ts}]{C.RESET} {C.GREEN}[DONE]{C.RESET} {color}{filename}{C.RESET} ({format_size(size)}) in {elapsed:.1f}s @ {format_speed(avg)}")
            print(f"{C.GRAY}[{ts}]{C.RESET} {C.CYAN}[MD5]{C.RESET} {md5}")
            transfer_log.append({
                "time": ts, "type": "DOWN", "file": filename,
                "size": format_size(size), "client": self.client_address[0], "md5": md5,
            })
        except Exception as e:
            err(f"send file: {filename} - {e}")

    def do_PUT(self):
        try:
            ts = timestamp()
            filename = os.path.basename(urllib.parse.unquote(self.path))
            filepath = os.path.join(self.upload_dir, filename)
            length = int(self.headers.get("Content-Length", 0))

            print(f"{C.GRAY}[{ts}]{C.RESET} {C.YELLOW}[PUT]{C.RESET} {filename} <- {self.client_address[0]}")
            pb = ProgressBar(filename, length, "UP")
            with open(filepath, "wb") as f:
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    f.write(chunk)
                    remaining -= len(chunk)
                    pb.update(len(chunk))
            pb.finish()

            md5 = get_md5(filepath)
            color = get_file_color(filename)
            print(f"{C.GRAY}[{ts}]{C.RESET} {C.GREEN}[UP]{C.RESET} {color}{filename}{C.RESET} ({format_size(length)})")
            print(f"{C.GRAY}[{ts}]{C.RESET} {C.CYAN}[MD5]{C.RESET} {md5}")
            print(f"{C.GRAY}[{ts}]{C.RESET} {C.BLUE}[SAVE]{C.RESET} {filepath}")

            transfer_log.append({
                "time": ts, "type": "UP", "file": filename,
                "size": format_size(length), "client": self.client_address[0], "md5": md5,
            })

            response = f"Uploaded: {filename} ({format_size(length)})\nMD5: {md5}\n".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
        except Exception as e:
            err(f"upload error: {e}")
            self.send_error(500, str(e))

    def do_POST(self):
        try:
            ts = timestamp()
            ctype = self.headers.get("Content-Type", "")
            length = int(self.headers.get("Content-Length", 0))

            if "multipart/form-data" in ctype:
                uploaded = self._parse_multipart(ctype, length, ts)
                if uploaded:
                    response = f"Uploaded: {', '.join(uploaded)}\n".encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(response)))
                    self.end_headers()
                    self.wfile.write(response)
                else:
                    self.send_error(400, "No files uploaded")
            else:
                # Raw POST body
                filename = os.path.basename(urllib.parse.unquote(self.path)) or f"upload_{int(time.time())}"
                filepath = os.path.join(self.upload_dir, filename)
                pb = ProgressBar(filename, length, "UP")
                with open(filepath, "wb") as f:
                    remaining = length
                    while remaining > 0:
                        chunk = self.rfile.read(min(CHUNK_SIZE, remaining))
                        if not chunk:
                            break
                        f.write(chunk)
                        remaining -= len(chunk)
                        pb.update(len(chunk))
                pb.finish()
                md5 = get_md5(filepath)
                color = get_file_color(filename)
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.GREEN}[UP]{C.RESET} {color}{filename}{C.RESET} ({format_size(length)})")
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.CYAN}[MD5]{C.RESET} {md5}")
                transfer_log.append({
                    "time": ts, "type": "UP", "file": filename,
                    "size": format_size(length), "client": self.client_address[0], "md5": md5,
                })
                response = f"Uploaded: {filename} ({format_size(length)})\nMD5: {md5}\n".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)
        except Exception as e:
            err(f"POST error: {e}")
            self.send_error(500, str(e))

    def log_message(self, format, *args):
        pass  # Silence default logging — we have our own

    def _parse_multipart(self, ctype, length, ts):
        """Parse multipart/form-data upload. Works with or without cgi module."""
        uploaded = []

        if HAS_CGI:
            # Legacy path (Python < 3.13)
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={"REQUEST_METHOD": "POST", "CONTENT_TYPE": ctype},
            )
            if "files" in form:
                items = form["files"]
                if not isinstance(items, list):
                    items = [items]
                for item in items:
                    if item.filename:
                        filename = os.path.basename(item.filename)
                        filepath = os.path.join(self.upload_dir, filename)
                        data = item.file.read()
                        with open(filepath, "wb") as f:
                            f.write(data)
                        self._log_upload(filepath, filename, len(data), ts)
                        uploaded.append(filename)
            return uploaded

        # Modern path (Python 3.13+) — use email parser
        # Read raw body, prepend Content-Type header so email module can parse
        body = self.rfile.read(length)
        msg_bytes = b"Content-Type: " + ctype.encode() + b"\r\n\r\n" + body
        msg = email.message_from_bytes(msg_bytes)
        if msg.is_multipart():
            for part in msg.walk():
                disposition = part.get("Content-Disposition", "")
                if "form-data" not in disposition or "filename=" not in disposition:
                    continue
                # Extract filename
                m = re.search(r'filename="([^"]+)"', disposition)
                if not m:
                    continue
                filename = os.path.basename(m.group(1))
                if not filename:
                    continue
                data = part.get_payload(decode=True) or b""
                filepath = os.path.join(self.upload_dir, filename)
                with open(filepath, "wb") as f:
                    f.write(data)
                self._log_upload(filepath, filename, len(data), ts)
                uploaded.append(filename)
        return uploaded

    def _log_upload(self, filepath, filename, size, ts):
        md5 = get_md5(filepath)
        color = get_file_color(filename)
        print(f"{C.GRAY}[{ts}]{C.RESET} {C.GREEN}[UP]{C.RESET} {color}{filename}{C.RESET} ({format_size(size)})")
        print(f"{C.GRAY}[{ts}]{C.RESET} {C.CYAN}[MD5]{C.RESET} {md5}")
        print(f"{C.GRAY}[{ts}]{C.RESET} {C.BLUE}[SAVE]{C.RESET} {filepath}")
        transfer_log.append({
            "time": ts, "type": "UP", "file": filename,
            "size": format_size(size), "client": self.client_address[0], "md5": md5,
        })


# =============================================================================
# SMB server detection & launch
# =============================================================================

def find_smb_server_command():
    """
    Returns the command list to start an SMB server, or None if not found.
    Tries:
      1. impacket-smbserver        (Kali; Arch after fix-impacket symlinks)
      2. smbserver.py              (Arch /usr/bin/)
      3. python3 -m impacket.examples.smbserver  (anywhere impacket is importable)
    """
    if shutil.which("impacket-smbserver"):
        return ["impacket-smbserver"]
    if shutil.which("smbserver.py"):
        return ["smbserver.py"]
    # Last resort: invoke as Python module
    try:
        subprocess.check_output(
            [sys.executable, "-c", "import impacket.examples.smbserver"],
            stderr=subprocess.DEVNULL,
        )
        return [sys.executable, "-m", "impacket.examples.smbserver"]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def smb_output_reader(proc, smb_user=None):
    """Read SMB subprocess output, classify and color-print events."""
    seen_ips = set()
    conn_times = {}
    RETRY_WINDOW = 10
    RETRY_THRESHOLD = 4

    conn_ip = None
    conn_authed_user = None

    def warn_smb(ts, msg):
        print(f"{C.GRAY}[{ts}]{C.RESET} {C.RED}{C.BOLD}[SMB] [!]{C.RESET} {C.YELLOW}{msg}{C.RESET}")

    def extract_ip(text):
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+),", text)
        return m.group(1) if m else None

    def extract_auth_user(text):
        m = re.search(r"AUTHENTICATE_MESSAGE\s*\(([^,]+),", text)
        return m.group(1) if m else None

    skip_substrings = (
        "Config file parsed", "Callback added", "Installation Path",
        "Impacket Library", "Copyright",
    )

    try:
        for line in proc.stdout:
            text = line.rstrip()
            if not text or any(s in text for s in skip_substrings):
                continue
            ts = timestamp()

            # CONN
            if "Incoming connection" in text:
                conn_ip = extract_ip(text)
                conn_authed_user = None
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.GREEN}[SMB CONN]{C.RESET} {text}")
                if conn_ip:
                    if seen_ips and conn_ip not in seen_ips:
                        warn_smb(ts, f"New source IP {conn_ip}")
                    seen_ips.add(conn_ip)
                    now = time.time()
                    dq = conn_times.setdefault(conn_ip, deque())
                    dq.append(now)
                    while dq and now - dq[0] > RETRY_WINDOW:
                        dq.popleft()
                    if len(dq) >= RETRY_THRESHOLD:
                        warn_smb(ts, f"{conn_ip} - {len(dq)} conns in {RETRY_WINDOW}s: retry storm")

            # AUTH
            elif "AUTHENTICATE_MESSAGE" in text:
                conn_authed_user = extract_auth_user(text)
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.GREEN}[SMB AUTH]{C.RESET} {text}")
                if smb_user is None and conn_authed_user and not conn_authed_user.rstrip().endswith("$"):
                    warn_smb(ts, f"Domain creds on anonymous share: {conn_authed_user} - hash may be reusable")
            elif "authenticated successfully" in text:
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.GREEN}[SMB AUTH]{C.RESET} {text}")

            # HASH (NTLMv2)
            elif ("::" in text and len(text) > 30) or "NTLMv" in text:
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.RED}{C.BOLD}[SMB HASH]{C.RESET} {C.RED}{text}{C.RESET}")

            # SHARE
            elif "Connecting Share" in text:
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.CYAN}[SMB SHARE]{C.RESET} {text}")

            # FILE OPS
            elif any(x in text for x in ("SMB2_CREATE", "NTCreateAndX")):
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.CYAN}[SMB CREATE]{C.RESET} {text}")
            elif any(x in text for x in ("SMB2_READ", "ReadAndX")):
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.CYAN}[SMB READ]{C.RESET} {text}")
            elif any(x in text for x in ("SMB2_WRITE", "WriteAndX")):
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.BLUE}[SMB WRITE]{C.RESET} {text}")
            elif any(x in text.lower() for x in (".php", ".exe", ".ps1", ".bat", ".dll")):
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.CYAN}{C.BOLD}[SMB FILE]{C.RESET} {C.CYAN}{text}{C.RESET}")
            else:
                # Verbose / unclassified line
                print(f"{C.GRAY}[{ts}] [smb]{C.RESET} {C.GRAY}{text}{C.RESET}")
    except Exception as e:
        err(f"SMB reader exception: {e}")


def start_smb_server(share_path, share_name, port, user=None, password=None, no_smb2=False):
    """Launch impacket SMB server as subprocess; returns Popen object or None."""
    cmd_base = find_smb_server_command()
    if not cmd_base:
        err("No SMB server backend found.")
        err("  Kali/Debian: sudo apt install python3-impacket impacket-scripts")
        err("  Arch:        sudo pacman -S impacket")
        err("               (then run: tools-setup.sh fix-impacket)")
        return None

    cmd = list(cmd_base) + [share_name, share_path]
    if not no_smb2:
        cmd += ["-smb2support"]
    if port and int(port) != DEFAULT_SMB_PORT:
        cmd += ["-port", str(port)]
    if user and password:
        cmd += ["-username", user, "-password", password]

    info(f"Starting SMB: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        # Reader thread
        threading.Thread(
            target=smb_output_reader,
            args=(proc, user),
            daemon=True,
        ).start()
        time.sleep(0.5)  # Give it a moment to start or fail fast
        if proc.poll() is not None:
            err(f"SMB server exited immediately (code {proc.returncode})")
            return None
        ok(f"SMB share '{share_name}' running on port {port} (path: {share_path})")
        return proc
    except Exception as e:
        err(f"Failed to start SMB server: {e}")
        return None


# =============================================================================
# Cleanup
# =============================================================================

def cleanup(signum=None, frame=None):
    global smb_proc
    if smb_proc and smb_proc.poll() is None:
        info("Shutting down SMB server...")
        try:
            smb_proc.terminate()
            try:
                smb_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                smb_proc.kill()
        except Exception:
            pass
    print(f"\n{C.YELLOW}Bye{C.RESET}")
    sys.exit(0)


# =============================================================================
# Main
# =============================================================================

def main():
    global smb_proc

    parser = argparse.ArgumentParser(
        description="DualServe — HTTP & SMB file transfer server (cross-distro)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  tools.py                                 # HTTP only on tun0:80, picks dir
  tools.py -p 8080                         # custom HTTP port
  tools.py -dir /tmp/loot                  # serve from specific dir
  tools.py -smb                            # HTTP + SMB on tun0
  tools.py -smb -i eth0                    # use eth0 instead of prompting
  tools.py -smb -smbuser admin -smbpass pw # authenticated SMB

Environment overrides:
  TOOLS_DIR=/path                          # default download dir base
  TOOLS_DEFAULT_IFACE=eth0                 # default in interface picker
  TOOLS_FORCE_IFACE=tun0                   # skip picker, force this iface

Cross-distro support:
  Kali/Debian: needs python3-impacket + impacket-scripts
  Arch:        needs impacket; run 'tools-setup.sh fix-impacket' once
""",
    )
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_HTTP_PORT, help=f"HTTP port (default: {DEFAULT_HTTP_PORT})")
    parser.add_argument("-dir", "--dir", default=None, help="Download directory (default: $TOOLS_DIR/http-smb-server or cwd)")
    parser.add_argument("-i", "--iface", default=None, help="Network interface to bind to (skips picker)")
    parser.add_argument("--no-prompt", action="store_true", help="Don't prompt for interface, use default or first")

    parser.add_argument("-smb", "--smb", action="store_true", help="Also start SMB server")
    parser.add_argument("-sp", "--smb-port", type=int, default=DEFAULT_SMB_PORT, help=f"SMB port (default: {DEFAULT_SMB_PORT})")
    parser.add_argument("-smbshare", "--smb-share", default=DEFAULT_SMB_SHARE, help=f"SMB share name (default: {DEFAULT_SMB_SHARE})")
    parser.add_argument("-smbuser", "--smb-user", default=None, help="SMB username (anonymous if not set)")
    parser.add_argument("-smbpass", "--smb-pass", default=None, help="SMB password")
    parser.add_argument("--no-smb2", action="store_true", help="Disable SMB2 protocol")

    args = parser.parse_args()

    # Resolve download dir
    download_dir = os.path.abspath(args.dir or _default_download_dir())
    if not os.path.isdir(download_dir):
        err(f"Download directory does not exist: {download_dir}")
        sys.exit(1)
    upload_dir = os.getcwd()

    # Pick interface
    iface_name, iface_ip = pick_interface(
        force_iface=args.iface,
        prompt=not args.no_prompt,
    )

    # Banner
    print()
    print(f"{C.BOLD}{C.CYAN}╔══════════════════════════════════════════════╗{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}║      DualServe — HTTP & SMB File Transfer    ║{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}╚══════════════════════════════════════════════╝{C.RESET}")
    print(f"  {C.BOLD}Interface:{C.RESET}     {iface_name} ({iface_ip})")
    print(f"  {C.BOLD}HTTP:{C.RESET}          http://{iface_ip}:{args.port}/")
    print(f"  {C.BOLD}Browse:{C.RESET}        http://{iface_ip}:{args.port}/files")
    print(f"  {C.BOLD}Log:{C.RESET}           http://{iface_ip}:{args.port}/log")
    print(f"  {C.BOLD}Download dir:{C.RESET}  {download_dir}")
    print(f"  {C.BOLD}Upload dir:{C.RESET}    {upload_dir} (cwd)")

    # Show files
    files = get_all_files_recursive(download_dir)
    print()
    print_files_table(files)

    # SMB
    if args.smb:
        print()
        smb_proc = start_smb_server(
            share_path=download_dir,
            share_name=args.smb_share,
            port=args.smb_port,
            user=args.smb_user,
            password=args.smb_pass,
            no_smb2=args.no_smb2,
        )
        if smb_proc:
            print(f"  {C.BOLD}SMB:{C.RESET}           \\\\{iface_ip}\\{args.smb_share} (port {args.smb_port})")

    # Quick-copy commands
    print()
    print(f"{C.YELLOW}Client commands:{C.RESET}")
    print(f"  {C.GRAY}# Linux:{C.RESET}")
    print(f"  curl http://{iface_ip}:{args.port}/<file> -o <file>")
    print(f"  wget http://{iface_ip}:{args.port}/<file>")
    print(f"  curl -T <file> http://{iface_ip}:{args.port}/  # upload (PUT)")
    print(f"  {C.GRAY}# PowerShell:{C.RESET}")
    print(f"  iwr http://{iface_ip}:{args.port}/<file> -O <file>")
    print(f"  certutil -urlcache -split -f http://{iface_ip}:{args.port}/<file>")
    if args.smb and smb_proc:
        print(f"  {C.GRAY}# SMB (Windows):{C.RESET}")
        print(f"  copy \\\\{iface_ip}\\{args.smb_share}\\<file> .")
        print(f"  net use Z: \\\\{iface_ip}\\{args.smb_share}")

    # Setup HTTP server
    DualHandler.upload_dir = upload_dir
    DualHandler.download_dir = download_dir
    DualHandler.server_ip = iface_ip
    DualHandler.server_port = args.port

    # Bind
    try:
        httpd = HTTPServer(("0.0.0.0", args.port), DualHandler)
    except PermissionError:
        err(f"Cannot bind port {args.port} (need root for ports < 1024). Try -p 8080")
        cleanup()
    except OSError as e:
        err(f"Bind error on port {args.port}: {e}")
        cleanup()

    # Signal handlers
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    print(f"\n{C.GREEN}Server running. Ctrl+C to stop.{C.RESET}\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        cleanup()


if __name__ == "__main__":
    main()
