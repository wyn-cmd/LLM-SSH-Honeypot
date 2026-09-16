# Intelligent LLM-Driven SSH Honeypot

An advanced, highly interactive, production-grade SSH honeypot built in Python utilizing Paramiko and the Google Gemini API. Designed to capture, analyze, and engage advanced persistent threats and automated scanners by dynamically simulating a complete Debian/Ubuntu Linux operating system environment with real-time AI fallback capabilities.

---

## Architecture & Core Design

Traditional honeypots rely on static canned responses or heavy virtual machines. This project bridges local deterministic emulation with generative AI to create a fluid, highly believable target:

1. **Virtual Filesystem (VFS):** Each incoming SSH connection receives an isolated, mutable clone of a standard Linux directory tree (`/`, `/bin`, `/usr/bin`, `/root`, `/home`, `/etc`, `/var/www/html`, `/proc`, `/dev`, `/tmp`). Actions such as `touch`, `mkdir`, `rm`, file redirection (`>`), and `cd` modify the session state in real-time.
2. **Deterministic Local Simulation:** Common system reconnaissance commands (`ls`, `cat`, `pwd`, `whoami`, `uname`, `id`, `date`, `ps`, `netstat`, `df`, `free`, `history`, `env`, `apt-get`, `python3`) execute locally with authentic output formatting.
3. **LLM Generative Fallback:** When a command falls outside local simulation rules, the honeypot securely queries the Google Gemini API (incorporating robust model fallback chains and strict RPM pacing delays) to generate realistic system responses on the fly.
4. **Threat Intelligence & Telemetry:** All authentication attempts, command executions, file modifications, package manager actions, and URL download staging attempts are logged into structured JSON telemetry (`honeypot_attacks.json`) for forensic analysis.

---

## Key Features

- **Session-Isolated Virtual Filesystem:** Supports absolute and relative path resolution, directory traversal (`..`), and persistent file state creation per session.
- **Advanced Terminal Emulation:**
  - Full Backspace/DEL character erasure and screen redrawing.
  - Tab autocompletion for files and directories within the current working directory.
  - Up and Down arrow key command history cycling.
  - Ctrl+C interrupt signal interception (`^C`) and ANSI escape sequence filtering.
  - Dynamic shell prompts (`root@ubuntu-srv:~#` vs `ubuntu@ubuntu-srv:~$`) with working `su` user switching.
- **Malware Staging Interception:** Captures and logs external payload download attempts (`wget`, `curl`) with realistic transfer simulation logs.
- **Rate-Limiting & RPM Pacing:** Built-in execution delays (`time.sleep`) prior to API requests to ensure strict adherence to rate limits.
- **Multi-Model Fallback Engine:** Automatically cycles through available high-performance flash models (`gemini-3.6-flash`, `gemini-3.1-flash-lite`, `gemini-3.5-flash-lite`, etc.) to prevent API service disruptions.

---

## Installation & Setup

### Prerequisites

- Python 3.10+
- Pip and virtualenv support

### 1. Clone & Initialize Environment

```bash
git clone https://github.com/your-repo/llm-ai-honeypot.git
cd llm-ai-honeypot
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure API Credentials

Set your Gemini API key in the environment before execution:

```bash
export GEMINI_API_KEY="your-gemini-api-key-here"
```

---

## Operational Usage

### Starting the Honeypot Server

To bind the SSH honeypot to port 2222:

```bash
python honeypot.py --port 2222
```

To bind to standard port 22 (requires root privileges):

```bash
sudo python honeypot.py --port 22
```

### Connecting from a Remote Client

```bash
ssh root@localhost -p 2222
```

---

## Telemetry & Logging Format

All security events and interaction metrics are recorded in `honeypot_attacks.json`. Example schema entry:

```json
{
  "timestamp": "2026-09-16T12:34:56.789012",
  "client_ip": "192.168.1.100",
  "username": "root",
  "session_user": "root",
  "event": "command_executed",
  "command": "cat /etc/passwd",
  "cwd": "/root"
}
```

## License

MIT License
