import os

# Resolve path to blacklist.txt in the same folder as this script
blacklist_file = os.path.join(os.path.dirname(__file__), 'blacklist.txt')
BLACKLIST = []

print(f"[DEBUG] Current directory: {os.getcwd()}")
print(f"[DEBUG] Expected blacklist path: {blacklist_file}")
print(f"[DEBUG] First 5 entries in blacklist: {BLACKLIST[:5]}")


# Load blacklist from file once
try:
    with open(blacklist_file, 'r', encoding='utf-8') as f:
        BLACKLIST = [line.strip().lower() for line in f if line.strip()]
    print(f"[DEBUG] Loaded {len(BLACKLIST)} blacklist entries")
except Exception as e:
    print(f"[ERROR] Could not load blacklist.txt: {e}")

# signature.py

def detect_signature_based(command):
    try:
        with open("blacklist.txt", "r", encoding="utf-8") as file:
            blacklist = [line.strip().lower() for line in file if line.strip()]
    except FileNotFoundError:
        return False

    command_lower = command.lower()
    return any(entry in command_lower for entry in blacklist)



def load_blacklist(path="blacklist.txt"):
    with open(path, "r", encoding="utf-8") as file:
        return [line.strip().lower() for line in file if line.strip()]

def is_malicious(command, blacklist):
    command_lower = command.lower()
    return any(entry in command_lower for entry in blacklist)
