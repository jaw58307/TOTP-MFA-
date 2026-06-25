"""
app.py - Flask application: all routes for the TOTP MFA system
"""
from flask import Flask, request, jsonify

from models import db, User
from totp_service import (
    generate_totp_secret,
    generate_qr_code_base64,
    confirm_enrollment,
)
from auth_service import (
    hash_password,
    login_step1_password,
    login_step2_totp,
    require_full_auth,
    invalidate_session,
)

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///totp_mfa.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "change-me-in-production"

db.init_app(app)

with app.app_context():
    db.create_all()


# ══════════════════════════════════════════════════════════════════════════════
# ■  PHASE 1 – Registration & Enrollment (one-time setup)
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/auth/register")
def register():
    """
    1a. Create account + generate TOTP secret.

    Body: { "username": "...", "email": "...", "password": "..." }

    Returns a base64 QR-code image the user scans with their authenticator app.
    The secret is stored server-side; it never travels to the client in raw form.
    """
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    email    = (data.get("email")    or "").strip()
    password =  data.get("password") or ""

    if not all([username, email, password]):
        return jsonify(error="username, email, and password are required."), 400

    if User.query.filter(
        (User.username == username) | (User.email == email)
    ).first():
        return jsonify(error="Username or email already taken."), 409

    # ── Generate cryptographic TOTP secret ────────────────────────────────
    secret = generate_totp_secret()

    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        totp_secret=secret,
        mfa_enabled=True,
        mfa_verified=False,          # not confirmed until enrollment step
    )
    db.session.add(user)
    db.session.commit()

    # ── Return QR code (base64 PNG) for the authenticator app ─────────────
    qr_b64 = generate_qr_code_base64(secret, username, issuer="MyApp")

    return jsonify(
        message=(
            "Account created. Scan the QR code with your authenticator app, "
            "then POST your first 6-digit token to /auth/enroll to complete setup."
        ),
        qr_code_base64=qr_b64,          # embed as: <img src="data:image/png;base64,<qr_b64>">
        # secret=secret  ← never expose in production; shown here for local demo only
    ), 201


@app.post("/auth/enroll")
def enroll():
    """
    1b. Confirm enrollment by verifying the first TOTP token.

    The user opens their authenticator app, reads the 6-digit code, and sends it.
    This proves the secret is correctly loaded before we mark MFA as verified.

    Body: { "username": "...", "token": "123456" }
    """
    data     = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    token    = (data.get("token")    or "").strip()

    user = User.query.filter_by(username=username).first()
    if not user or not user.totp_secret:
        return jsonify(error="User not found or TOTP not initialised."), 404

    if user.mfa_verified:
        return jsonify(message="MFA already enrolled."), 200

    ok, msg = confirm_enrollment(user.totp_secret, token)
    if not ok:
        return jsonify(error=msg), 400

    user.mfa_verified = True
    db.session.commit()
    return jsonify(message=msg), 200


# ══════════════════════════════════════════════════════════════════════════════
# ■  PHASE 2 – Login Verification Loop (every login)
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/auth/login")
def login_step1():
    """
    2a. Password verification.

    On success the session is placed in MFA_PENDING state and a
    short-lived pending_token is returned (valid for 10 min).

    Body: { "username": "...", "password": "..." }
    """
    data     = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    password =  data.get("password") or ""

    ok, msg, payload = login_step1_password(username, password)

    if not ok:
        return jsonify(error=msg), 401

    return jsonify(message=msg, **payload), 200


@app.post("/auth/verify-mfa")
def login_step2():
    """
    2b. TOTP verification – unlocks the full session.

    Body: { "pending_token": "...", "totp_token": "123456" }
    """
    data          = request.get_json(force=True)
    pending_token = (data.get("pending_token") or "").strip()
    totp_token    = (data.get("totp_token")    or "").strip()

    ok, msg, payload = login_step2_totp(pending_token, totp_token)

    if not ok:
        return jsonify(error=msg), 401

    return jsonify(message=msg, **payload), 200


# ══════════════════════════════════════════════════════════════════════════════
# ■  Protected endpoint example
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/dashboard")
def dashboard():
    """
    A protected resource that requires a FULLY_AUTHENTICATED session.
    Pass the session token in the Authorization header:
        Authorization: Bearer <session_token>
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify(error="Missing Authorization header."), 401

    token = auth_header.removeprefix("Bearer ").strip()
    ok, user, err = require_full_auth(token)

    if not ok:
        return jsonify(error=err), 401

    return jsonify(
        message=f"Welcome to the dashboard, {user.username}!",
        user=user.username,
        email=user.email,
    ), 200


@app.post("/auth/logout")
def logout():
    """Invalidate the current session."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.removeprefix("Bearer ").strip()
        invalidate_session(token)
    return jsonify(message="Logged out."), 200


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=5000)
