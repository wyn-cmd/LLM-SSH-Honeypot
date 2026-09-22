import os
import sys
import socket
import threading
import paramiko
import json
import datetime
import argparse
import time
import copy
from google import genai
from google.genai import types
from rich.console import Console
from rich.panel import Panel

console = Console()

API_KEY = os.environ.get("GEMINI_API_KEY")
if not API_KEY:
    console.print("[bold red][!] Error: GEMINI_API_KEY environment variable is not set.[/bold red]")
    sys.exit(1)

client = genai.Client(api_key=API_KEY)

KEY_FILE = "server.key"
if not os.path.exists(KEY_FILE):
    host_key = paramiko.RSAKey.generate(2048)
    host_key.write_private_key_file(KEY_FILE)
else:
    host_key = paramiko.RSAKey(filename=KEY_FILE)

LOG_FILE = "honeypot_attacks.json"
ALERT_FILE = "alerts.log"

def log_attack(data):
    """Append security event telemetry to JSON log file."""
    logs = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    logs.append(data)
    try:
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=2)
    except OSError as e:
        console.print(f"[red][-] Failed to write attack log: {e}[/red]")

def log_alert(message):
    """Write high-priority security alerts to alert log file."""
    timestamp = datetime.datetime.now().isoformat()
    alert_entry = f"[{timestamp}] ALERT: {message}\n"
    try:
        with open(ALERT_FILE, "a", encoding="utf-8") as f:
            f.write(alert_entry)
    except OSError:
        pass
    console.print(f"[bold red][SECURITY ALERT] {message}[/bold red]")

class HoneypotServer(paramiko.ServerInterface):
    """Paramiko server interface for handling SSH authentication and channels."""
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.username = ""
        self.password = ""

    def check_auth_password(self, username, password):
        """Accept all passwords and log authentication attempts."""
        self.username = username
        self.password = password
        console.print(f"[bold red][!] Auth attempt from {self.client_ip} | User: {username} | Pass: {password}[/bold red]")
        log_attack({
            "timestamp": datetime.datetime.now().isoformat(),
            "client_ip": self.client_ip,
            "event": "auth_attempt",
            "username": username,
            "password": password
        })
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        """Accept public key authentication attempts."""
        self.username = username
        console.print(f"[bold yellow][!] Public key auth attempt from {self.client_ip} | User: {username}[/bold yellow]")
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        """Approve incoming session channel requests."""
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        """Approve shell invocation requests."""
        return True

    def check_channel_pty_request(self, channel, term, width, height, pxwidth, pxheight, modes):
        """Approve pseudo-terminal allocation requests."""
        return True

FULL_LINUX_VFS = {
    "/": {
        "type": "dir",
        "contents": {
            "bin": {
                "type": "dir",
                "contents": {
                    "ls": "[ELF binary]",
                    "cat": "[ELF binary]",
                    "pwd": "[ELF binary]",
                    "whoami": "[ELF binary]",
                    "hostname": "[ELF binary]",
                    "uname": "[ELF binary]",
                    "bash": "[ELF binary]",
                    "sh": "[ELF binary]",
                    "rm": "[ELF binary]",
                    "mkdir": "[ELF binary]",
                    "touch": "[ELF binary]",
                    "grep": "[ELF binary]",
                    "find": "[ELF binary]",
                    "clear": "[ELF binary]",
                    "ping": "[ELF binary]"
                }
            },
            "usr": {
                "type": "dir",
                "contents": {
                    "bin": {
                        "type": "dir",
                        "contents": {
                            "python3": "[ELF binary]",
                            "curl": "[ELF binary]",
                            "wget": "[ELF binary]",
                            "netstat": "[ELF binary]",
                            "ps": "[ELF binary]",
                            "top": "[ELF binary]",
                            "apt-get": "[ELF binary]",
                            "pip": "[ELF binary]",
                            "su": "[ELF binary]",
                            "sudo": "[ELF binary]",
                            "nano": "[ELF binary]",
                            "vim": "[ELF binary]",
                            "iptables": "[ELF binary]"
                        }
                    }
                }
            },
            "root": {
                "type": "dir",
                "contents": {
                    "flag.txt": "FLAG{llm_honeypot_captured_you_1337}\n",
                    ".bash_history": "ls -la\ncd app\ncat main.py\nwhoami\nuname -a\n",
                    ".bashrc": "# ~/.bashrc: executed by bash(1) for non-login shells.\nexport PS1='\\u@\\h:\\w\\$ '\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n",
                    "backup.tar.gz": "[binary gzip archive data]\n",
                    ".aws": {
                        "type": "dir",
                        "contents": {
                            "credentials": "[default]\laws_access_key_id = AKIAIOSFODNN7EXAMPLE\laws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                        }
                    },
                    "app": {
                        "type": "dir",
                        "contents": {
                            "main.py": "import os\nprint('Backend service operational')\n",
                            "requirements.txt": "flask==3.0.0\nrequests==2.31.0\n"
                        }
                    }
                }
            },
            "home": {
                "type": "dir",
                "contents": {
                    "ubuntu": {
                        "type": "dir",
                        "contents": {
                            ".bashrc": "# Ubuntu default bashrc\n",
                            "notes.txt": "Check firewall configurations.\n"
                        }
                    }
                }
            },
            "etc": {
                "type": "dir",
                "contents": {
                    "passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nubuntu:x:1000:1000:Ubuntu,,,:/home/ubuntu:/bin/bash\n",
                    "shadow": "root:$6$rounds=5000$saltsalt$encryptedhashstringhere:19000:0:99999:7:::\ndaemon:*:18000:0:99999:7:::\n",
                    "group": "root:x:0:\nubuntu:x:1000:\n",
                    "hosts": "127.0.0.1 localhost ubuntu-srv\n::1 localhost ip6-localhost ip6-loopback\n",
                    "hostname": "ubuntu-srv\n",
                    "resolv.conf": "nameserver 8.8.8.8\nnameserver 1.1.1.1\n",
                    "issue": "Ubuntu 22.04.3 LTS \\n \\l\n",
                    "os-release": "NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\nID=ubuntu\nID_LIKE=debian\n"
                }
            },
            "var": {
                "type": "dir",
                "contents": {
                    "www": {
                        "type": "dir",
                        "contents": {
                            "html": {
                                "type": "dir",
                                "contents": {
                                    "index.php": "<?php echo 'Web portal online'; ?>\n",
                                    "config.php": "<?php $db_pass = 'secret_db_password_99'; ?>\n",
                                    "robots.txt": "User-agent: *\nDisallow: /admin/\n"
                                }
                            }
                        }
                    },
                    "log": {
                        "type": "dir",
                        "contents": {
                            "auth.log": "Oct 12 10:00:01 ubuntu-srv sshd[1337]: Accepted password for root from 192.168.1.50 port 54321 ssh2\n",
                            "syslog": "Oct 12 10:00:00 ubuntu-srv systemd[1]: Started System Logging Service.\n"
                        }
                    }
                }
            },
            "tmp": {
                "type": "dir",
                "contents": {
                    "test.sh": "#!/bin/bash\necho 'Running test script'\n"
                }
            },
            "proc": {
                "type": "dir",
                "contents": {
                    "version": "Linux version 5.15.0-88-generic (buildd@lcy02-amd64-053) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU 2.38)) #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023\n",
                    "cpuinfo": "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel name\t: Intel(R) Xeon(R) CPU @ 2.80GHz\n",
                    "meminfo": "MemTotal:       4046208 kB\nMemFree:        1524104 kB\n"
                }
            },
            "dev": {
                "type": "dir",
                "contents": {
                    "null": "[character device]",
                    "zero": "[character device]",
                    "urandom": "[character device]"
                }
            }
        }
    }
}

def resolve_path(cwd, path):
    """Resolve relative or absolute paths against current working directory."""
    if not path:
        return cwd
    if path.startswith("/"):
        parts = [p for p in path.split("/") if p]
    else:
        parts = [p for p in cwd.split("/") if p] + [p for p in path.split("/") if p]
    
    resolved = []
    for p in parts:
        if p == "..":
            if resolved:
                resolved.pop()
        elif p != "." and p:
            resolved.append(p)
    return "/" + "/".join(resolved)

def get_node_by_path(vfs_root, path):
    """Retrieve virtual filesystem node dictionary or file content by absolute path."""
    parts = [p for p in path.split("/") if p]
    curr = vfs_root["/"]
    if not parts:
        return curr
    for p in parts:
        if curr.get("type") == "dir" and "contents" in curr and p in curr["contents"]:
            curr = curr["contents"][p]
        else:
            return None
    return curr

def simulate_command(command, session_state):
    """Simulate common Linux commands locally within the virtual filesystem."""
    cmd_trimmed = command.strip()
    parts = cmd_trimmed.split()
    cmd_name = parts[0] if parts else ""
    cwd = session_state["cwd"]
    vfs = session_state["vfs"]

    if any(kw in cmd_trimmed.lower() for kw in ["base64", "chmod +x", "wget", "curl", "nc ", "bash -i", "python3 -c", "shadow"]):
        log_alert(f"Suspicious command detected from IP {session_state.get('client_ip', 'unknown')}: {cmd_trimmed}")

    if "shadow" in cmd_trimmed or "credentials" in cmd_trimmed or "id_rsa" in cmd_trimmed:
        log_alert(f"HONEYTOKEN TRIPPED! Attacker accessed sensitive file target: {cmd_trimmed} from IP {session_state.get('client_ip', 'unknown')}")

    if cmd_name == "su":
        target_user = parts[1] if len(parts) > 1 else "root"
        if target_user in ["ubuntu", "guest"]:
            session_state["user"] = target_user
            session_state["cwd"] = f"/home/{target_user}"
            return ""
        elif target_user == "root":
            session_state["user"] = "root"
            session_state["cwd"] = "/root"
            return ""
        else:
            return f"su: user {target_user} does not exist"

    if cmd_name == "sudo":
        if len(parts) > 1:
            sub_cmd = " ".join(parts[1:])
            return simulate_command(sub_cmd, session_state)
        else:
            return "usage: sudo -h | -K | -k | -V"

    if ">" in parts or ">>" in parts:
        mode = ">>" if ">>" in parts else ">"
        idx = parts.index(mode)
        content_parts = parts[:idx]
        target_file = parts[idx+1] if idx+1 < len(parts) else ""
        file_content = " ".join(content_parts).strip()
        if (file_content.startswith('"') and file_content.endswith('"')) or (file_content.startswith("'") and file_content.endswith("'")):
            file_content = file_content[1:-1]
        
        if content_parts and content_parts[0] == "echo":
            file_content = " ".join(content_parts[1:]).strip()
            if (file_content.startswith('"') and file_content.endswith('"')) or (file_content.startswith("'") and file_content.endswith("'")):
                file_content = file_content[1:-1]

        target_path = resolve_path(cwd, target_file)
        parent_dir_path = os.path.dirname(target_path) or "/"
        filename = os.path.basename(target_path)

        parent_node = get_node_by_path(vfs, parent_dir_path)
        if parent_node and parent_node.get("type") == "dir":
            if mode == ">" or filename not in parent_node["contents"]:
                parent_node["contents"][filename] = file_content + "\n"
            else:
                existing = parent_node["contents"][filename]
                if isinstance(existing, str):
                    parent_node["contents"][filename] = existing + file_content + "\n"
                else:
                    parent_node["contents"][filename] = file_content + "\n"
            return ""
        else:
            return f"bash: {target_file}: No such file or directory"

    if cmd_name == "pwd":
        return cwd
    elif cmd_name == "whoami":
        return session_state["user"]
    elif cmd_name == "hostname":
        return "ubuntu-srv"
    elif cmd_name == "id":
        usr = session_state["user"]
        uid = "0(root)" if usr == "root" else "1000(ubuntu)"
        gid = "0(root)" if usr == "root" else "1000(ubuntu)"
        return f"uid={uid} gid={gid} groups={gid}"
    elif cmd_name in ["uname", "uname -a"]:
        return "Linux ubuntu-srv 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
    elif cmd_name == "date":
        return datetime.datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y")
    elif cmd_name == "cd":
        target = parts[1] if len(parts) > 1 else ("~" if session_state["user"] == "root" else f"/home/{session_state['user']}")
        if target == "~" or target == "":
            new_path = "/root" if session_state["user"] == "root" else f"/home/{session_state['user']}"
        else:
            new_path = resolve_path(cwd, target)
        
        node = get_node_by_path(vfs, new_path)
        if node and node.get("type") == "dir":
            session_state["cwd"] = new_path
            return ""
        else:
            return f"cd: {target}: No such file or directory"
    elif cmd_name in ["ls", "ll"]:
        target_dir = cwd
        if len(parts) > 1 and not parts[1].startswith("-"):
            target_dir = resolve_path(cwd, parts[1])
        
        node = get_node_by_path(vfs, target_dir)
        if node and node.get("type") == "dir":
            contents = node["contents"]
            items = list(contents.keys())
            lines = [f"total {len(items) * 4}"]
            for item in sorted(items):
                sub = contents[item]
                is_dir = isinstance(sub, dict) and sub.get("type") == "dir"
                perms = "drwx------" if is_dir else "-rw-r--r--"
                size = "4096" if is_dir else str(len(sub)) if isinstance(sub, str) else "220"
                lines.append(f"{perms}  1 {session_state['user']} {session_state['user']} {size} Oct 12 10:00 {item}")
            return "\n".join(lines)
        else:
            target_arg = parts[1] if len(parts) > 1 else target_dir
            return f"ls: cannot access '{target_arg}': No such file or directory"
    elif cmd_name == "cat":
        if len(parts) < 2:
            return "cat: missing file operand"
        target_path = resolve_path(cwd, parts[1])
        parent_dir_path = os.path.dirname(target_path) or "/"
        filename = os.path.basename(target_path)
        
        parent_node = get_node_by_path(vfs, parent_dir_path)
        if parent_node and parent_node.get("type") == "dir" and filename in parent_node["contents"]:
            sub = parent_node["contents"][filename]
            if isinstance(sub, str):
                return sub.strip()
            else:
                return f"cat: {parts[1]}: Is a directory"
        else:
            return f"cat: {parts[1]}: No such file or directory"
    elif cmd_name == "touch":
        if len(parts) < 2:
            return "touch: missing file operand"
        for target in parts[1:]:
            target_path = resolve_path(cwd, target)
            parent_dir_path = os.path.dirname(target_path) or "/"
            filename = os.path.basename(target_path)
            parent_node = get_node_by_path(vfs, parent_dir_path)
            if parent_node and parent_node.get("type") == "dir":
                if filename not in parent_node["contents"]:
                    parent_node["contents"][filename] = ""
        return ""
    elif cmd_name == "mkdir":
        if len(parts) < 2:
            return "mkdir: missing operand"
        for target in parts[1:]:
            target_path = resolve_path(cwd, target)
            parent_dir_path = os.path.dirname(target_path) or "/"
            dirname = os.path.basename(target_path)
            parent_node = get_node_by_path(vfs, parent_dir_path)
            if parent_node and parent_node.get("type") == "dir":
                new_dir = {"type": "dir", "contents": {}}
                parent_node["contents"][dirname] = new_dir
        return ""
    elif cmd_name in ["rm", "rmdir"]:
        if len(parts) < 2:
            return f"{cmd_name}: missing operand"
        target_path = resolve_path(cwd, parts[1])
        parent_dir_path = os.path.dirname(target_path) or "/"
        filename = os.path.basename(target_path)
        parent_node = get_node_by_path(vfs, parent_dir_path)
        if parent_node and parent_node.get("type") == "dir" and filename in parent_node["contents"]:
            del parent_node["contents"][filename]
            return ""
        else:
            return f"{cmd_name}: failed to remove '{parts[1]}': No such file or directory"
    elif cmd_name == "iptables":
        return "Chain INPUT (policy ACCEPT)\nnum  target     prot opt source               destination\n\nChain FORWARD (policy ACCEPT)\nnum  target     prot opt source               destination\n\nChain OUTPUT (policy ACCEPT)\nnum  target     prot opt source               destination"
    elif cmd_name in ["nano", "vim", "vi"]:
        target_file = parts[1] if len(parts) > 1 else "unnamed.txt"
        target_path = resolve_path(cwd, target_file)
        parent_dir_path = os.path.dirname(target_path) or "/"
        filename = os.path.basename(target_path)
        parent_node = get_node_by_path(vfs, parent_dir_path)
        file_data = ""
        if parent_node and parent_node.get("type") == "dir" and filename in parent_node["contents"]:
            file_data = parent_node["contents"][filename]
        return f"\033[H\033[J--- [ Simulated Editor: {filename} ] ---\n{file_data}\n[ Read {len(file_data.splitlines())} lines ]\n^G Get Help  ^O WriteOut  ^R Read File  ^Y Prev Pg  ^K Cut Text  ^C Cur Pos\n^X Exit"
    elif cmd_name == "ping":
        host = parts[1] if len(parts) > 1 else "localhost"
        return f"PING {host} (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.035 ms\n64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.041 ms\n64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.038 ms\n\n--- {host} ping statistics ---\n3 packets transmitted, 3 received, 0% packet loss, time 2045ms\nrtt min/avg/max/mdev = 0.035/0.038/0.041/0.002 ms"
    elif cmd_name == "clear":
        return "\033[H\033[J"
    elif cmd_name == "ps":
        return "  PID TTY          TIME CMD\n 1337 pts/0    00:00:00 bash\n 1450 pts/0    00:00:00 python3"
    elif cmd_name in ["apt-get", "apt", "pip"]:
        pkg_action = " ".join(parts[1:]) if len(parts) > 1 else "update"
        console.print(f"[bold yellow][PACKAGE MANAGER] Action executed: {cmd_name} {pkg_action}[/bold yellow]")
        log_attack({
            "timestamp": datetime.datetime.now().isoformat(),
            "event": "package_manager_action",
            "command": command
        })
        return f"Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\nCalculating upgrade... Done\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."
    elif cmd_name in ["wget", "curl"]:
        url = parts[1] if len(parts) > 1 else "unknown"
        console.print(f"[bold magenta][MALWARE STAGED] Payload download requested from URL: {url}[/bold magenta]")
        log_attack({
            "timestamp": datetime.datetime.now().isoformat(),
            "event": "file_download_attempt",
            "command": command,
            "url": url
        })
        return f"--{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}\nResolving {url} (localhost)... 127.0.0.1\nConnecting to {url}|127.0.0.1|:80... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 1337 (1.3K) [application/octet-stream]\nSaving to: 'payload'\n\npayload             100%[===================>]   1.33K  --.-KB/s    in 0s      \n\n2026-09-16 10:00:00 (133 MB/s) - 'payload' saved [1337/1337]"
    elif cmd_name == "history":
        hist_lines = session_state.get("history", [])
        return "\n".join([f"  {idx+1}  {h}" for idx, h in enumerate(hist_lines)])
    elif cmd_name == "env":
        usr = session_state["user"]
        home = f"/home/{usr}" if usr != "root" else "/root"
        return f"SHELL=/bin/bash\nPWD={cwd}\nLOGNAME={usr}\nHOME={home}\nTERM=xterm-256color\nUSER={usr}\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    elif cmd_name == "df":
        return "Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/sda1       20642408  4128480  15457544  22% /"
    elif cmd_name == "free":
        return "               total        used        free      shared  buff/cache   available\nMem:         4046208     1024320     1524104       12304     1497784     2801456\nSwap:          2097152          0     2097152"
    elif cmd_name == "python3" and len(parts) == 1:
        return "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n>>> print('Interactive shell active')\nInteractive shell active\n>>> exit()"
    return None

def send_output(channel, text):
    """Normalize line endings to CRLF and send text across SSH channel."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="ignore")
    formatted = text.replace("\r\n", "\n").replace("\n", "\r\n")
    if not formatted.endswith("\r\n") and not text.endswith("\r"):
        formatted += "\r\n"
    try:
        channel.send(formatted.encode("utf-8"))
    except Exception:
        pass

def handle_ssh_session(client_sock, client_addr):
    """Handle incoming SSH client connection and interactive shell loop."""
    client_ip = client_addr[0]
    console.print(f"[bold green][+] Incoming connection from {client_ip}:{client_addr[1]}[/bold green]")
    
    transport = paramiko.Transport(client_sock)
    transport.add_server_key(host_key)
    server = HoneypotServer(client_ip)
    
    try:
        transport.start_server(server=server)
    except Exception as e:
        console.print(f"[red][-] SSH transport error: {e}[/red]")
        transport.close()
        return

    channel = transport.accept(20)
    if not channel:
        console.print(f"[yellow][-] No channel opened for {client_ip}[/yellow]")
        transport.close()
        return

    send_output(channel, "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)\n")
    
    session_state = {
        "user": "root",
        "cwd": "/root",
        "vfs": copy.deepcopy(FULL_LINUX_VFS),
        "history": [],
        "command_count": 0,
        "start_time": datetime.datetime.now(),
        "client_ip": client_ip
    }

    system_prompt = (
        "You are an interactive Linux terminal on a remote Ubuntu 22.04 LTS server. "
        "The server is a slightly misconfigured web development node with hostname ubuntu-srv and root user. "
        "When the user types shell commands, reply ONLY with the exact text output that a real Linux terminal would produce. "
        "Do not break character, do not add conversational pleasantries or warnings. "
        "Simulate file listings, errors, command results, and outputs realistically."
    )

    while True:
        try:
            cwd = session_state["cwd"]
            usr = session_state["user"]
            sign = "#" if usr == "root" else "$"
            home_dir = "/root" if usr == "root" else f"/home/{usr}"
            if cwd == home_dir:
                display_cwd = "~"
            elif cwd.startswith(home_dir + "/"):
                display_cwd = "~" + cwd[len(home_dir):]
            else:
                display_cwd = cwd

            prompt = f"{usr}@ubuntu-srv:{display_cwd}{sign} "
            try:
                channel.send(prompt.encode("utf-8"))
            except Exception:
                break
            
            command_bytes = bytearray()
            in_escape = False
            escape_buf = bytearray()
            hist_idx = len(session_state["history"])

            while True:
                try:
                    chunk = channel.recv(1024)
                except Exception:
                    chunk = b""
                if not chunk:
                    break
                for b in chunk:
                    if in_escape:
                        escape_buf.append(b)
                        if len(escape_buf) >= 2:
                            seq = bytes(escape_buf)
                            if seq == b'[A':
                                history = session_state["history"]
                                if history and hist_idx > 0:
                                    hist_idx -= 1
                                    send_output(channel, f"\r\x1b[K{prompt}{history[hist_idx]}")
                                    command_bytes = bytearray(history[hist_idx].encode('utf-8'))
                            elif seq == b'[B':
                                history = session_state["history"]
                                if history and hist_idx < len(history) - 1:
                                    hist_idx += 1
                                    send_output(channel, f"\r\x1b[K{prompt}{history[hist_idx]}")
                                    command_bytes = bytearray(history[hist_idx].encode('utf-8'))
                                else:
                                    hist_idx = len(history)
                                    send_output(channel, f"\r\x1b[K{prompt}")
                                    command_bytes = bytearray()
                            in_escape = False
                            escape_buf.clear()
                        continue

                    if b == 27:
                        in_escape = True
                        escape_buf.clear()
                        escape_buf.append(b)
                        continue
                    elif b == 3:
                        send_output(channel, "^C\r\n")
                        command_bytes = bytearray()
                        in_escape = False
                        break
                    elif b in (127, 8):
                        if len(command_bytes) > 0:
                            command_bytes.pop()
                            send_output(channel, "\b \b")
                    elif b in (10, 13):
                        send_output(channel, "\r\n")
                        break
                    elif b == 9:
                        partial = command_bytes.decode('utf-8', errors='ignore')
                        token = partial.split()[-1] if partial.split() else ""
                        vfs = session_state["vfs"]
                        node = get_node_by_path(vfs, cwd)
                        if node and node.get("type") == "dir" and "contents" in node:
                            matches = [c for c in node["contents"].keys() if c.startswith(token)]
                            if len(matches) == 1:
                                completion = matches[0][len(token):]
                                command_bytes.extend(completion.encode('utf-8'))
                                send_output(channel, completion)
                            elif len(matches) > 1:
                                send_output(channel, "\r\n" + "  ".join(matches) + "\r\n" + prompt + partial)
                    else:
                        command_bytes.append(b)
                        try:
                            channel.send(bytes([b]))
                        except Exception:
                            pass

                if command_bytes.endswith(b"\n") or command_bytes.endswith(b"\r") or (chunk and (b'\n' in chunk or b'\r' in chunk) and not in_escape):
                    break
                if len(command_bytes) == 0 and (b'\n' in chunk or b'\r' in chunk):
                    break
            
            command = command_bytes.decode("utf-8", errors="ignore").strip()
            if not command:
                continue
                
            session_state["history"].append(command)
            session_state["command_count"] += 1
            console.print(f"[bold cyan][CMD] {client_ip} ({session_state['user']}) -> {command}[/bold cyan]")
            
            log_attack({
                "timestamp": datetime.datetime.now().isoformat(),
                "client_ip": client_ip,
                "username": server.username,
                "session_user": session_state["user"],
                "event": "command_executed",
                "command": command,
                "cwd": cwd
            })

            if command.lower() in ["exit", "quit", "logout"]:
                send_output(channel, "Connection closed.")
                break

            output = simulate_command(command, session_state)

            if output is None:
                try:
                    console.print("[yellow][*] Pacing before Gemini API call (respecting RPM)...[/yellow]")
                    time.sleep(2.0)
                    
                    fallback_models = [
                        "gemini-3.6-flash",
                        "gemini-3.1-flash-lite",
                        "gemini-3.5-flash-lite",
                        "gemini-2.5-flash-lite",
                        "gemini-2.0-flash-exp",
                        "gemini-1.5-flash"
                    ]
                    
                    resp = None
                    for m in fallback_models:
                        try:
                            chat = client.chats.create(
                                model=m,
                                config=types.GenerateContentConfig(
                                    system_instruction=system_prompt,
                                    temperature=0.3
                                )
                            )
                            resp = chat.send_message(f"Current user: {session_state['user']}, Current directory: {session_state['cwd']}. User executed command: {command}")
                            if resp and resp.text:
                                break
                        except Exception:
                            continue
                    
                    output = resp.text if resp and resp.text else f"bash: {command}: command not found"
                except Exception as e:
                    console.print(f"[red][- ] Gemini API error: {e}[/red]")
                    output = f"bash: {command}: command not found"

            if output:
                send_output(channel, output)
            
        except Exception:
            break

    duration = (datetime.datetime.now() - session_state["start_time"]).total_seconds()
    console.print(f"[bold yellow][SESSION SUMMARY] IP: {client_ip} | Duration: {duration:.1f}s | Commands executed: {session_state['command_count']}[/bold yellow]")
    log_attack({
        "timestamp": datetime.datetime.now().isoformat(),
        "event": "session_disconnected",
        "client_ip": client_ip,
        "duration_seconds": duration,
        "commands_executed": session_state["command_count"]
    })

    try:
        channel.close()
    except Exception:
        pass
    try:
        transport.close()
    except Exception:
        pass
    console.print(f"[dim][- ] Connection closed for {client_ip}[/dim]")

def main():
    """Start TCP server and spawn worker threads for incoming SSH connections."""
    parser = argparse.ArgumentParser(description="LLM-Powered Intelligent SSH Honeypot")
    parser.add_argument("--host", default="0.0.0.0", help="Listen host")
    parser.add_argument("--port", type=int, default=2222, help="Listen port")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((args.host, args.port))
    except OSError as e:
        console.print(f"[bold red][!] Error binding to {args.host}:{args.port}: {e}[/bold red]")
        sys.exit(1)

    sock.listen(100)

    console.print(Panel(f"Advanced Linux Honeypot Active on {args.host}:{args.port}", border_style="magenta"))

    while True:
        try:
            client_sock, client_addr = sock.accept()
            t = threading.Thread(target=handle_ssh_session, args=(client_sock, client_addr))
            t.daemon = True
            t.start()
        except KeyboardInterrupt:
            console.print("\n[bold yellow][*] Shutting down honeypot server...[/bold yellow]")
            break
        except Exception as e:
            console.print(f"[red][- ] Error accepting connection: {e}[/red]")

    try:
        sock.close()
    except Exception:
        pass

if __name__ == "__main__":
    main()