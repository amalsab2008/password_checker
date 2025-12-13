# 🔐 Password Strength Checker (CLI)

A security-focused **command-line password strength checker** written in Python.  
Designed using real-world cybersecurity principles such as entropy estimation, pattern detection, and large-scale common-password analysis.

---

## ✨ Features Overview

This tool evaluates password strength using:

- 🔢 Entropy estimation  
- 🔠 Character-set analysis  
- 📕 Common password detection using **RockYou**  
- 🌸 Bloom filter acceleration (millions of passwords in milliseconds)  
- 🔁 Sequence detection (`abcd`, `1234`, keyboard rows)  
- 🔂 Repetition detection (`aaaa`, `ababab`)  
- 📅 Date-like password detection (`1999`, `2020`)  
- 📄 JSON & CSV output modes  
- 🔐 Secure interactive mode (using `getpass`)  

---

## 🚀 Quick Start

### 🔹 Interactive mode
```bash
python3 password_checker.py --interactive

🔹 Check passwords from a file

python3 password_checker.py --file example/passwords.txt

🔹 JSON output (pipe-friendly)

python3 password_checker.py --file example/passwords.txt \
  --json --no-examples 2>/dev/null | jq

⚡ Bloom Filter (Fast Common-Password Checking)
Build once (slow, one-time operation)

python3 password_checker.py --rockyou /usr/share/wordlists/rockyou.txt \
  --bloom --build-bloom --bloom-cache bloom.gz

Use the saved Bloom filter (fast)

python3 password_checker.py --rockyou /usr/share/wordlists/rockyou.txt \
  --bloom --bloom-cache bloom.gz \
  --file example/passwords.txt \
  --json --no-examples 2>/dev/null | jq

⏱ Bloom filter loads in ~0.03 seconds, making it ideal for:

    Automation pipelines

    API servers

    Large-scale password audits

🛡 Security Note

The Bloom cache file (bloom.gz) uses pickle, which can execute code when loaded.

⚠️ Only load Bloom cache files you created yourself.
🚫 Never load Bloom files from untrusted sources.

The file bloom.gz is already added to .gitignore and must not be committed.
🔧 Install Dependencies

pip install -r requirements.txt

