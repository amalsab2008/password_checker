# Password Strength Checker (Interactive CLI)

A local, privacy-friendly password strength checker written in Python.  
It evaluates password entropy, detects common passwords, sequences, repeated patterns, and gives actionable feedback.

## Features
- ✔ Interactive CLI (secure input using `getpass`)
- ✔ File input mode (`--file`)
- ✔ JSON or CSV output
- ✔ Optional rockyou.txt integration
- ✔ Optional Bloom filter for memory-efficient large list checking
- ✔ No data leaves your machine — everything is processed locally

---

## Usage

### Interactive Mode:
```bash
python3 password_checker.py --interactive

Check a file of passwords:

python3 password_checker.py --file passwords.txt --csv results.csv

Use rockyou.txt (local file only):

python3 password_checker.py --rockyou /path/to/rockyou.txt --bloom

###Installation

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

###Security Notes

    Do not upload real passwords online.

    Do not commit rockyou.txt — it stays local.

    The tool prints passwords to screen; avoid testing sensitive real-world passwords.

###License

MIT License. See LICENSE.


Save:  
`CTRL + O` → Enter →  
Exit: `CTRL + X`

## Bloom filter cache for fast common-password checks

This project supports a memory-efficient Bloom filter for fast membership tests against large lists (e.g. `rockyou.txt`).

### Build a Bloom filter (one-time)
```bash
python3 password_checker.py --rockyou /path/to/rockyou.txt --bloom --build-bloom --bloom-cache bloom.gz


---


