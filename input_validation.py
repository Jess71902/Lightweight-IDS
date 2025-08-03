import re

def validate_command(command):
    if len(command.strip()) == 0:
        return False
    if re.search(r"[^\w\s\.\-:/]", command):  # basic input sanitation
        return False
    return True
