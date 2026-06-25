"""
demo.py - End-to-end walkthrough of the TOTP MFA system (no HTTP required).
Run with:  python demo.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask
from models import db, User
from totp_service import (
    generate_totp_secret,
    generate_qr_code_base64,
    get_current_totp,
    confirm_enrollment,
)
from auth_service import (
    hash_password,
    login_step1_password,
    login_step2_totp,
    require_full_auth,
)

# ── Bootstrap a minimal Flask app for the demo ────────────────────────────────
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///demo_totp.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

SEP = "─" * 60

def section(title: str):
    print(f"\n{SEP}\n  {title}\n{SEP}")


with app.app_context():
    db.create_all()

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 1  ─  Registration & Enrollment
    # ══════════════════════════════════════════════════════════════════════════

    section("PHASE 1a – User Registration")

    # Simulate the backend generating a unique cryptographic key
    secret = generate_totp_secret()
    print(f"  ✔  Generated TOTP secret  : {secret}")

    # Build QR code (in a real app, this PNG is served to the frontend)
    qr_b64 = generate_qr_code_base64(secret, username="alice", issuer="MyApp")
    print(f"  ✔  QR code base64 length  : {len(qr_b64)} chars (embed as <img> in HTML)")

    # Persist user
    user = User(
        username="alice",
        email="alice@example.com",
        password_hash=hash_password("hunter2"),
        totp_secret=secret,
        mfa_enabled=True,
        mfa_verified=False,
    )
    db.session.add(user)
    db.session.commit()
    print(f"  ✔  User saved to database  (id={user.id})")

    # ──────────────────────────────────────────────────────────────────────────
    section("PHASE 1b – Enrollment Confirmation")

    # Alice scans the QR code; her authenticator app generates the first code
    first_code = get_current_totp(secret)
    print(f"  ✔  Current TOTP code (simulated from app): {first_code}")

    ok, msg = confirm_enrollment(secret, first_code)
    print(f"  ✔  Enrollment result: {msg}")

    if ok:
        user.mfa_verified = True
        db.session.commit()
        print("  ✔  mfa_verified=True saved.")

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 2  ─  Login Verification Loop
    # ══════════════════════════════════════════════════════════════════════════

    section("PHASE 2a – Step 1: Password Verification")

    ok, msg, payload = login_step1_password("alice", "hunter2")
    print(f"  ✔  {msg}")
    print(f"     state         : {payload['state']}")
    print(f"     mfa_required  : {payload['mfa_required']}")

    pending_token = payload.get("pending_token")
    print(f"     pending_token : {pending_token[:20]}…")

    # ──────────────────────────────────────────────────────────────────────────
    section("PHASE 2b – Step 2: TOTP Verification")

    live_code = get_current_totp(secret)
    print(f"  ✔  Alice's authenticator shows: {live_code}")

    ok, msg, payload = login_step2_totp(pending_token, live_code)
    print(f"  ✔  {msg}")
    if payload:
        print(f"     state         : {payload['state']}")
        session_token = payload.get("session_token")
        print(f"     session_token : {session_token[:20]}…")

    # ──────────────────────────────────────────────────────────────────────────
    section("Accessing a Protected Resource")

    auth_ok, authed_user, err = require_full_auth(session_token)
    if auth_ok:
        print(f"  ✔  Access GRANTED to {authed_user.username} ({authed_user.email})")
    else:
        print(f"  ✗  Access DENIED: {err}")

    # ──────────────────────────────────────────────────────────────────────────
    section("Attack Simulation – Wrong TOTP on a Fresh Login")

    _, _, p2 = login_step1_password("alice", "hunter2")
    bad_ok, bad_msg, _ = login_step2_totp(p2["pending_token"], "000000")
    print(f"  ✗  Attack result: {bad_msg}")

    section("Demo Complete")
    print("  All phases exercised successfully.\n")
