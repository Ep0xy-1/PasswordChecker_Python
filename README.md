# 🔐 Password Strength + Breach Checker (Tkinter GUI)

A simple cybersecurity tool built with Python and Tkinter. This application evaluates the **strength** of a password based on modern security standards and checks it against the **Have I Been Pwned** API to detect if it has ever appeared in real-world data breaches.

---

## 📦 Features

✅ **Password Strength Evaluation**  
- Enforces 5 key criteria:
  - Minimum length (8+ characters)
  - Uppercase letters
  - Lowercase letters
  - Numbers
  - Special characters

✅ **Breach Detection (Privacy-Safe)**  
- Uses **SHA-1 hashing** with prefix-only queries to the [Pwned Passwords API](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange)
- Never sends the full password or full hash online
- Displays how many times the password appeared in breaches (if any)

✅ **Modern GUI Interface**  
- Responsive UI with real-time results
- Threaded backend to avoid freezing
- Copy-safe, CLI-free for end users

✅ **Production-Ready Code**  
- No string toy logic; full real-world implementations
- Uses `requests`, `hashlib`, `re`, `threading`, and `tkinter`

---

## 🛠️ Installation

```bash```
git clone https://github.com/yourusername/password-breach-checker.git
cd password-breach-checker
pip install requests
python app.py
Note: Tkinter comes pre-installed with Python. If not:

sudo apt install python3-tk    # Linux
brew install python-tk         # macOS

# 🔍 Example Output

Password Strength:
[✓] Minimum length of 8 characters → PASS
[✓] Contains an uppercase letter → PASS
[✓] Contains a lowercase letter → PASS
[✓] Contains a digit → PASS
[✓] Contains a special character → PASS

➡️  Total Score: 5/5

Checking against known breaches...
✅ No known breach found. Your password is unique (for now).

# 📁 File Structure
password-checker/
│
├── app.py           # Main GUI code
├── README.md
└── screenshot.png   # Optional UI image

# 🤝 Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change or add.



created in 19/07/2025
