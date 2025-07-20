import tkinter as tk
from tkinter import ttk, messagebox
import re
import hashlib
import requests
import threading

 
# Constants
STRENGTH_RULES = {
    "min_length": lambda p: len(p) >= 8,
    "uppercase": lambda p: bool(re.search(r"[A-Z]", p)),
    "lowercase": lambda p: bool(re.search(r"[a-z]", p)),
    "digits": lambda p: bool(re.search(r"[0-9]", p)),
    "special_char": lambda p: bool(re.search(r"[\W_]", p))
}

MESSAGES = {
    "min_length": "Minimum length of 8 characters",
    "uppercase": "Contains an uppercase letter",
    "lowercase": "Contains a lowercase letter",
    "digits": "Contains a digit",
    "special_char": "Contains a special character"
}


class PasswordChecker:
    def __init__(self, password: str):
        self.password = password
        self.score = 0
        self.details = {}

    def evaluate_strength(self):
        self.details = {}
        self.score = 0
        for rule, check_fn in STRENGTH_RULES.items():
            result = check_fn(self.password)
            self.details[rule] = result
            self.score += int(result)
        return self.details, self.score

    def get_sha1_hash(self):
        hashed = hashlib.sha1(self.password.encode('utf-8')).hexdigest().upper()
        return hashed[:5], hashed[5:]

    def query_pwned_api(self, prefix):
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            raise ConnectionError(f"API Error: {e}")

    def check_breach(self):
        prefix, suffix = self.get_sha1_hash()
        response = self.query_pwned_api(prefix)
        hashes = (line.split(':') for line in response.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)
        return 0


class PasswordApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength & Breach Checker")
        self.root.geometry("550x450")
        self.root.resizable(False, False)

        self.setup_ui()

    def setup_ui(self):
        ttk.Label(self.root, text="🔐 Enter Password:", font=("Segoe UI", 12)).pack(pady=10)

        self.entry_var = tk.StringVar()
        self.entry = ttk.Entry(self.root, textvariable=self.entry_var, show="*", width=40)
        self.entry.pack(pady=5)

        self.check_btn = ttk.Button(self.root, text="Check Password", command=self.start_check)
        self.check_btn.pack(pady=10)

        self.result_text = tk.Text(self.root, height=15, width=65, state="disabled", bg="#f4f4f4", font=("Consolas", 10))
        self.result_text.pack(pady=10)

    def start_check(self):
        pwd = self.entry_var.get()
        if not pwd.strip():
            messagebox.showerror("Error", "Password cannot be empty.")
            return

        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, "Evaluating password...\n")
        self.result_text.config(state="disabled")

        # Run in thread to avoid freezing GUI
        threading.Thread(target=self.run_check, args=(pwd,), daemon=True).start()

    def run_check(self, password):
        checker = PasswordChecker(password)

        details, score = checker.evaluate_strength()
        output = f"Password Strength:\n"
        for rule, passed in details.items():
            mark = "✓" if passed else "✗"
            status = "PASS" if passed else "FAIL"
            output += f"[{mark}] {MESSAGES[rule]} → {status}\n"

        output += f"\n➡️  Total Score: {score}/5\n\n"
        output += f"Checking against known breaches (API)...\n"

        try:
            count = checker.check_breach()
            if count:
                output += f"🚨 BREACHED! Found {count:,} times in data leaks.\n"
            else:
                output += f"✅ No known breach found. Your password is unique (for now).\n"
        except Exception as e:
            output += f"❗ Error checking breach: {str(e)}\n"

        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, output)
        self.result_text.config(state="disabled")


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordApp(root)
    root.mainloop()
