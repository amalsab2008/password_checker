✨ Password Strength Checker – Features Overview

This project is a CLI-based security tool that evaluates password strength using:

Entropy estimation

Character-set analysis

Common password detection using RockYou

Bloom filter acceleration (millions of passwords in milliseconds)

Sequence detection (abcd, 1234, keyboard rows)

Repetition detection (aaaa, ababab)

Date-like password detection (1999, 2020)

JSON & CSV output modes

Interactive secure-mode (using getpass)

🚀 Quick Start
Interactive mode
python3 password_checker.py --interactive

Check passwords from a file
python3 password_checker.py --file example/passwords.txt

JSON output (pipe-friendly)
python3 password_checker.py --file example/passwords.txt --json --no-examples 2>/dev/null | jq

⚡ Bloom Filter (Fast Common-Password Checking)
Build once (slow, one-time):
python3 password_checker.py --rockyou /usr/share/wordlists/rockyou.txt \
    --bloom --build-bloom --bloom-cache bloom.gz

Use the saved bloom (fast):
python3 password_checker.py --rockyou /usr/share/wordlists/rockyou.txt \
    --bloom --bloom-cache bloom.gz \
    --file example/passwords.txt --json --no-examples 2>/dev/null | jq


Bloom filter loads in 0.03s, ideal for automation, API servers, or large-scale password audits.

🛡 Security Note

The bloom cache file (bloom.gz) uses pickle, which can execute code when loaded.
Only load bloom files you created yourself.

Do not commit bloom.gz — it is already added to .gitignore.

🔧 Install Dependencies
pip install -r requirements.txt

🎯 GitHub Actions – Python Test Badge

Add this badge at the top of your README:

![Tests](https://github.com/USERNAME/password_checker/actions/workflows/python-tests.yml/badge.svg)


Replace USERNAME with your GitHub username:
→ amalsab2008

Final badge link:

![Tests](https://github.com/amalsab2008/password_checker/actions/workflows/python-tests.yml/badge.svg)


Save the file (Ctrl+O → Enter → Ctrl+X).
