# detection/rule.py
import re

def detect_rule_based(command):
    rules = [
        r"powershell.*Invoke-WebRequest",
        r"curl\\s+http",
        r"wget\\s+http"
    ]
    for rule in rules:
        if re.search(rule, command, re.IGNORECASE):
            return True
    return False
