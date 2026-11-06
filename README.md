# Expense Tracking V3

## Run
1. Extract the ZIP.
2. Serve the folder from localhost or HTTPS (service workers and Web Crypto require a secure context).
3. Open the app in a modern browser and create a profile with a six-digit PIN.

For a quick local server, run `python -m http.server 8000` in this folder and visit `http://localhost:8000`.

## Included
- Profile: full name, birth date, automatically calculated age, profile picture, category (Student / Business / Trader / Teenager), six-digit PIN.
- Add, edit, and delete income/expense transactions.
- Month/year/all-time transaction filters and year/month reports.
- Expense category bar chart.
- Excel-compatible CSV export and browser Print / Save as PDF.
- AES-GCM encryption at rest using a PIN-derived key (PBKDF2-SHA-256, 310,000 iterations).

## Important
- Records are stored only in this browser on this device. No cloud sync or recovery.
- Losing the PIN means the encrypted records cannot be unlocked.
- This is a personal local-first tracker, not a certified financial or security product.
- CSV is Excel-compatible, not a native `.xlsx` workbook. PDF export uses the browser print dialog.
- Use HTTPS or localhost for Web Crypto and service-worker support.
