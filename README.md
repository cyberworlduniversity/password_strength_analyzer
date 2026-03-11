# 🔐 Password Strength Analyzer

A comprehensive Python tool to analyze password security — built with only the Python standard library.

---

## ✨ Features

| Feature | Description |
|---|---|
| **Entropy Calculator** | Measures bits of randomness in a password |
| **Strength Meter** | Visual bar rating from Very Weak → Very Strong |
| **Complexity Check** | Validates length, case, digits, special chars |
| **Dictionary Detection** | Detects common passwords & keyboard walk patterns |
| **Leet-speak Detection** | Sees through `p@ssw0rd`-style substitutions |
| **Brute-Force Estimator** | Calculates crack time across 4 attack scenarios |
| **Hash Generator** | Shows MD5 / SHA-1 / SHA-256 digests (demo) |
| **Password Suggestions** | Generates cryptographically secure passwords |
| **Batch Mode** | Analyze a whole file of passwords at once |

---

## 🚀 Quick Start

### Requirements
- Python 3.10 or higher
- No external packages needed (standard library only)

### Installation

```bash
# 1. Clone or unzip the project
unzip password_strength_analyzer.zip
cd password_strength_analyzer

# 2. Run the interactive analyzer
python password_analyzer.py
```

---

## 📖 Usage

### Interactive Mode (recommended)

```bash
python password_analyzer.py
```

You will be prompted to enter a password. Input is hidden via `getpass`.

**Sample output:**

```
============================================================
        🔐 PASSWORD STRENGTH ANALYZER
============================================================

  Password : My***rd  (length: 10)
  Entropy  : 59.5 bits
  Charset  : 94 characters

  Strength : 🟡  Moderate  (score: 6)
  Meter    : [████████████░░░░░░░░░░░░░░░░░░]

─── Issues Found ────────────────────────────────────
  ⚠️  Contains common word/pattern: 'password'

─── Estimated Crack Time ────────────────────────────
  Online (throttled)             317.1 years
  Online (unthrottled)           3.2 years
  Offline (bcrypt)               3.2 years
  Offline (MD5/GPU)              Instantly

─── Improvement Suggestions ─────────────────────────
  ✅ Increase length to at least 12 characters.
  ✅ Try this strong password: zK#8mL!pQ2@nR5xT
  ✅ Or this one:              J!4vP@kW9nL#3mQ2xBdR
============================================================
```

---

### Batch Mode

Analyze a list of passwords from a text file (one per line):

```bash
python batch_check.py passwords.txt
```

Run the built-in demo:

```bash
python batch_check.py --demo
```

**Sample output:**

```
PASSWORD                       STRENGTH      ENTROPY  SCORE
-----------------------------------------------------------------
  pa***rd                      🔴 Very Weak     37.6      0
  P@***rd                      🟡 Moderate      52.7      5
  Tr***&3                      🟢 Strong        62.9      8
```

---

## 🧪 Running Tests

```bash
python -m pytest test_analyzer.py -v
# or without pytest:
python test_analyzer.py
```

---

## 📂 Project Structure

```
password_strength_analyzer/
│
├── password_analyzer.py   # Core analysis engine + interactive CLI
├── batch_check.py         # Batch password analysis from file
├── test_analyzer.py       # Unit tests (unittest)
├── requirements.txt       # Dependency list (stdlib only)
└── README.md              # This file
```

---

## 🔒 Security & Privacy

- Passwords are **never stored, logged, or transmitted**
- Input is hidden using Python's built-in `getpass` module
- Hashes shown are for demonstration purposes only
- Generated passwords use `secrets` module (cryptographically secure)

---

## 🧠 How Entropy Is Calculated

```
Entropy (bits) = log2(charset_size) × password_length
```

| Charset Used | Size |
|---|---|
| Lowercase only | 26 |
| + Uppercase | 52 |
| + Digits | 62 |
| + Special chars | 94 |

A minimum of **60 bits** is recommended for strong passwords.

---

## 📊 Brute-Force Scenarios

| Scenario | Speed |
|---|---|
| Online (throttled) | 100 guesses/sec |
| Online (unthrottled) | 10,000 guesses/sec |
| Offline (bcrypt) | 10,000 guesses/sec |
| Offline (MD5/GPU) | 10 billion guesses/sec |

---

## 🏢 Use Cases

- Developer password validation utilities
- Organization password policy enforcement
- Security awareness training demonstrations
- Automated password auditing in CI/CD pipelines

---

## 👤 Author

**hemanathan115**

---

## 📜 License

MIT License – free to use, modify, and distribute.
