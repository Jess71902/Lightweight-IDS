import datetime
import os

def alert_user(command, status):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"[{timestamp}] ALERT: [{status}] - {command}"

    # Define color codes for CLI
    COLORS = {
        "Malicious": "\033[91m",    # Red
        "Suspicious": "\033[93m",   # Yellow
        "Legitimate": "\033[92m",   # Green
        "Invalid input format": "\033[95m",  # Orange/Purple
        "RESET": "\033[0m"
    }

    color = COLORS.get(status, COLORS["RESET"])
    print(f"{color}{message}{COLORS['RESET']}")

    os.makedirs("logs", exist_ok=True)
    with open("logs/alerts.log", "a") as f:
        f.write(message + "\n")
