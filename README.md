# TOTP MFA Authentication Demo

A small Flask-based sample project demonstrating a two-step login flow using password authentication plus Time-based One-Time Password (TOTP) multi-factor authentication (MFA).

## Overview

This project provides:
- User registration with account creation and TOTP secret generation.
- Enrollment confirmation using a QR code for authenticator apps.
- Login flow with password verification followed by TOTP token verification.
- Protected endpoint access only after full MFA authentication.
- A standalone demo script showing the full end-to-end workflow.

## Project Structure

- `app.py` - Flask app with REST endpoints for registration, enrollment, login, MFA verification, and logout.
- `auth_service.py` - Password hashing, session state machine, MFA login logic, and protected session validation.
- `totp_service.py` - TOTP secret generation, QR code encoding, and token verification.
- `models.py` - SQLAlchemy models for user and session tracking.
- `demo.py` - Script that walks through registration, enrollment, login, MFA verification, and protected access.
- `requirements.txt` - Python dependencies.
- `README.txt` - This project readme.

## Requirements

- Python 3.8+ (recommended)
- `flask`
- `flask-sqlalchemy`
- `bcrypt`
- `pyotp`
- `qrcode[pil]`
- `pillow`

Install dependencies with:

```bash
pip install -r requirements.txt
```

## Getting Started

1. Install dependencies.
2. Run the Flask app:

```bash
python app.py
```

3. Open a REST client or use `curl` to interact with the API.

## API Endpoints

### Register a new user

`POST /auth/register`

Request body:

```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "hunter2"
}
```

Response includes a base64-encoded QR code image. Scan this with an authenticator app to enroll.

### Confirm MFA enrollment

`POST /auth/enroll`

Request body:

```json
{
  "username": "alice",
  "token": "123456"
}
```

This verifies the first token from the authenticator app and marks MFA as enrolled.

### Login with password

`POST /auth/login`

Request body:

```json
{
  "username": "alice",
  "password": "hunter2"
}
```

If MFA is enabled, the response returns a `pending_token` for the second step.

### Verify TOTP and complete login

`POST /auth/verify-mfa`

Request body:

```json
{
  "pending_token": "<pending_token>",
  "totp_token": "123456"
}
```

A successful response returns a `session_token` for protected access.

### Protected dashboard example

`GET /api/dashboard`

Requires header:

```
Authorization: Bearer <session_token>
```

### Logout

`POST /auth/logout`

Invalidates the current session token.

## Demo Script

Run the interactive demo without HTTP:

```bash
python demo.py
```

It creates a demo user, generates a TOTP secret, confirms enrollment, performs a login, verifies MFA, and tests protected access.

## Security Notes

- Passwords are hashed using `bcrypt`.
- TOTP secrets are generated with `pyotp` and stored server-side.
- The registration endpoint returns a QR code image in base64 so the secret is never exposed as raw text in production.
- Session state machine tracks `MFA_PENDING` and `FULLY_AUTHENTICATED` states.

## Notes

- The current `app.py` uses a SQLite database file `totp_mfa.db` and a hardcoded Flask secret key for demo purposes.
- In production, use an environment-configured secret key and a stronger database backend.
- Keep system clocks in sync when using TOTP authenticator apps.
