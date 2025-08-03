import re
import datetime
import os

# ------------------ Secure Validation ------------------
def validate_command(command):
    # Allow safe printable characters, avoid control chars
    pattern = r'^[\w\s:/._\-\\%\"\'=&?@]{3,500}$'
    if not re.match(pattern, command):
        return False

    # Still block known dangerous substrings
    forbidden = [';', '&&', '|', '`', '$(', '<', '>', 'rm ', 'shutdown', 'del ', 'format ', 'eval', 'exec']
    return not any(sym in command.lower() for sym in forbidden)

# ------------------ Rule-Based Detection ------------------

RULE_PATTERNS = [
    r"powershell\s+.*invoke-webrequest",
    r"curl\s+http",
    r"wget\s+http",
    r"powershell\s+-nop",
    r"nc\s+-lvp",
    r"scp\s+.+@.+:",
]

def detect_rule_based(command):
    for rule in RULE_PATTERNS:
        if re.search(rule, command, re.IGNORECASE):
            return True
    return False

# ------------------ Signature-Based Detection ------------------

BLACKLIST = [
    "powershell -encodedcommand",
    "powershell -enc",
    "wget evilfile.sh",
    "curl http://malicious-site.com",
    "curl http://untrusted-source.com",
    "certutil -urlcache",
    "invoke-webrequest http://exploit.com",
    "iex (new-object net.webclient)",
    "bash -i >& /dev/tcp/",
    "cmd /c start http://phishing.site",
]

def detect_signature_based(command: str) -> bool:
    command_lower = command.lower()
    return any(pattern in command_lower for pattern in BLACKLIST)

# ------------------ Alert Logging ------------------

def alert_user(command, status):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"[{timestamp}] ALERT: [{status.upper()}] - {command}"
    print(color_output(message, status))

    os.makedirs("logs", exist_ok=True)
    with open("logs/alerts.log", "a") as f:
        f.write(message + "\n")

def color_output(text, status):
    if status == "malicious":
        return f"\033[91m{text}\033[0m"  # Red
    elif status == "suspicious":
        return f"\033[93m{text}\033[0m"  # Yellow
    elif status == "legitimate":
        return f"\033[92m{text}\033[0m"  # Green
    else:
        return text
