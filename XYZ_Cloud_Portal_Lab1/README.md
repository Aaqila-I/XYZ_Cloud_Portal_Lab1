# XYZ Cloud Portal — Lab 1 (Baseline Portal)

This is the Lab 1 demo implementation for **Pearson BTEC HND — Applied Cryptography in the Cloud** module assessment scenario **“XYZ Cloud Solutions”** (US/UK/Canada branches).

## What Lab 1 Includes
- HTTP-only Flask web app
- Login with hardcoded users (hashed passwords)
- Branch-based isolation (US / UK / CA)
- Upload + list + download files (per branch)
- Server-side audit-style logs (console + `logs/audit.log`)
- Basic safe practices (allowed extensions, secure filenames, 10MB max upload)

## What Lab 1 Does NOT Include (for later labs)
- No TLS/PKI (Lab 2)
- No file encryption (Lab 3)
- No key management (Lab 4)
- No integrity/non-repudiation signatures (Lab 5)

## Setup
```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open: http://127.0.0.1:5000

## Test Accounts
All accounts use: `Password123!`

- `us.alex` (US)
- `uk.sana` (UK)
- `ca.mike` (CA)

## Storage
Files are stored under:
- `storage/US/`
- `storage/UK/`
- `storage/CA/`

## Notes for Lab 2 (TLS)
For certificate demonstrations, you can map a friendly hostname to localhost:
- `xyz.local` -> `127.0.0.1` in the Windows `hosts` file
Then you can issue a cert for `xyz.local` and run Flask with an SSL context.

(We intentionally do NOT enable TLS in Lab 1.)
