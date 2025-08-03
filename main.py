import tkinter as tk
from tkinter import messagebox, scrolledtext
from threading import Thread
import subprocess
import os
import time
import re
import shlex
from logic import validate_command, detect_rule_based, detect_signature_based, alert_user

def launch_gui():
    def check_command():
        user_input = entry.get().strip()
        if not user_input:
            messagebox.showwarning("Input Error", "Please enter a command or URL.")
            return
        detect_and_display(user_input)

    def clear_input():
        entry.delete(0, tk.END)
        result_label.config(text="Result:", fg="#2c3e50")
        entry.focus()

    def detect_and_display(command):
        if not validate_command(command):
            verdict = "Invalid input format"
            color = "#e67e22"
        elif detect_signature_based(command):
            verdict = "Malicious"
            color = "#e74c3c"
        elif detect_rule_based(command):
            verdict = "Suspicious"
            color = "#f39c12"
        else:
            verdict = "Legitimate"
            color = "#2ecc71"

        result_label.config(text=f"Result: {verdict}", fg=color)
        alert_user(command, verdict)

        # Execute command securely if not a URL
        try:
            if verdict == "Legitimate" and not re.match(r"^https?://", command, re.IGNORECASE):
                args = shlex.split(command)
                result = subprocess.run(args, capture_output=True, text=True, shell=False)
                print("[Execution Output]:", result.stdout)
        except Exception as e:
            print("[Secure Execution Error]", e)

    def monitor_real_time():
        global realtime_output, realtime_output_ready

        while not globals().get('realtime_output_ready', False):
            time.sleep(0.5)

        if 'realtime_output' not in globals():
            print("[Error] realtime_output not initialized.")
            return

        seen = set()

        while True:
            try:
                if os.name == 'nt':
                    output = subprocess.check_output('wmic process get CommandLine', shell=True, text=True)
                else:
                    output = subprocess.check_output(['ps', '-eo', 'args'], text=True)

                commands = output.strip().splitlines()

                for cmd in commands:
                    cmd = cmd.strip()
                    if not cmd or cmd.lower() == "commandline" or cmd in seen:
                        continue

                    seen.add(cmd)
                    if len(seen) > 1000:
                        seen.clear()

                    if not validate_command(cmd):
                        verdict = "Invalid input format"
                    elif detect_signature_based(cmd):
                        verdict = "Malicious"
                    elif detect_rule_based(cmd):
                        verdict = "Suspicious"
                    else:
                        verdict = "Legitimate"

                    timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
                    log_entry = f"{timestamp} ALERT: [{verdict}] - {cmd}\n"

                    print(log_entry.strip())

                    if realtime_output:
                        realtime_output.insert(tk.END, log_entry)
                        realtime_output.see(tk.END)

                    alert_user(cmd, verdict)

            except Exception as e:
                error_msg = f"[Monitor Error] {e}\n"
                print(error_msg.strip())
                if realtime_output:
                    realtime_output.insert(tk.END, error_msg)
                    realtime_output.see(tk.END)

            time.sleep(5)

    def open_realtime_window():
        global realtime_output, realtime_output_ready
        rt_win = tk.Toplevel(root)
        rt_win.title("Real-Time Detection Viewer")
        rt_win.geometry("700x300")
        rt_win.resizable(True, True)

        realtime_output = scrolledtext.ScrolledText(rt_win, wrap=tk.WORD, font=("Consolas", 10))
        realtime_output.pack(expand=True, fill='both')
        realtime_output_ready = True

    # ------------------ GUI Layout ------------------ #
    root = tk.Tk()
    root.title("MalCommandGuard - Input Scanner")
    root.geometry("600x280")
    root.resizable(False, False)

    tk.Label(root, text="MalCommandGuard", font=("Helvetica", 16, "bold"), fg="#2980b9").pack(pady=10)

    input_frame = tk.Frame(root)
    input_frame.pack(pady=5)

    tk.Label(input_frame, text="Enter a command or URL:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
    entry = tk.Entry(input_frame, width=60, font=("Arial", 10))
    entry.grid(row=1, column=0, padx=5, pady=5)
    entry.focus()

    button_frame = tk.Frame(root)
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="Check", width=12, command=check_command, bg="#60a5fa", fg="white").grid(row=0, column=0, padx=5)
    tk.Button(button_frame, text="Clear", width=12, command=clear_input, bg="#333333", fg="white").grid(row=0, column=1, padx=5)
    tk.Button(button_frame, text="Real-Time Log", width=12, command=open_realtime_window, bg="#16a085", fg="white").grid(row=0, column=2, padx=5)
    tk.Button(button_frame, text="Exit", width=12, command=root.destroy, bg="#e74c3c", fg="white").grid(row=0, column=3, padx=5)

    result_label = tk.Label(root, text="Result:", font=("Arial", 12, "bold"), fg="#2c3e50")
    result_label.pack(pady=10)

    monitor_thread = Thread(target=monitor_real_time, daemon=True)
    monitor_thread.start()

    root.mainloop()



if __name__ == "__main__":
    launch_gui()
