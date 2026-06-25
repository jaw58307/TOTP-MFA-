"""
auth_service.py - Password auth, session state machine, MFA verification
"""
import bcrypt
import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict

from models import db, User, Session
from totp_service import verify_totp_token


# ─────────────────────────────────────────────────────────────────────────────
# Password utilities
# ─────────────────────────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    """Hash a plaintext password with bcrypt (salt included in output)."""
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def check_password(plain: str, hashed: str) -> bool:
    """Constant-time bcrypt comparison."""
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# ─────────────────────────────────────────────────────────────────────────────
# Session helpers
# ─────────────────────────────────────────────────────────────────────────────

SESSION_TTL_MINUTES = 10          # MFA_PENDING sessions expire quickly
FULL_SESSION_TTL_HOURS = 8        # Fully authenticated sessions last 8 h


def _create_session(user: User, state: str, ttl_minutes: int) -> Session:
    token = secrets.token_urlsafe(64)
    session = Session(
        user_id=user.id,
        token=token,
        state=state,
        expires_at=datetime.utcnow() + timedelta(minutes=ttl_minutes),
    )
    db.session.add(session)
    db.session.commit()
    return session


def get_session(token: str) -> Optional[Session]:
    """Look up an active, non-expired session by token."""
    session = Session.query.filter_by(token=token, is_active=True).first()
    if session and session.expires_at < datetime.utcnow():
        session.is_active = False
        db.session.commit()
        return None
    return session


def invalidate_session(token: str) -> None:
    """Logout – mark session inactive."""
    session = Session.query.filter_by(token=token).first()
    if session:
        session.is_active = False
        db.session.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 – Login Verification Loop
# ─────────────────────────────────────────────────────────────────────────────

def login_step1_password(username: str, password: str) -> Tuple[bool, str, Optional[Dict]]:
    """
    STEP 1 – Password check.

    On success the session enters MFA_PENDING state.
    The caller receives a short-lived pending_token that ONLY unlocks step 2.

    Returns (ok, message, payload)
    """
    user = User.query.filter_by(username=username).first()

    # Generic error message prevents username enumeration
    if not user or not check_password(password, user.password_hash):
        return False, "Invalid username or password.", None

    # ── MFA not enrolled yet ──────────────────────────────────────────────
    if not user.mfa_enabled or not user.mfa_verified:
        # Issue a full session immediately (enrollment is required separately)
        session = _create_session(user, "FULLY_AUTHENTICATED", FULL_SESSION_TTL_HOURS * 60)
        return True, "Login successful (MFA not yet enrolled).", {
            "session_token": session.token,
            "state": session.state,
            "mfa_required": False,
        }

    # ── MFA enrolled – hold in MFA_PENDING ───────────────────────────────
    session = _create_session(user, "MFA_PENDING", SESSION_TTL_MINUTES)
    return True, "Password verified. Please submit your TOTP token.", {
        "pending_token": session.token,
        "state": session.state,
        "mfa_required": True,
    }


def login_step2_totp(pending_token: str, totp_token: str) -> Tuple[bool, str, Optional[Dict]]:
    """
    STEP 2 – TOTP verification.

    Accepts the pending_token from step 1, validates the 6-digit code,
    and on success upgrades the session to FULLY_AUTHENTICATED.

    Returns (ok, message, payload)
    """
    session = get_session(pending_token)

    if not session:
        return False, "Session not found or expired. Please log in again.", None

    if session.state != "MFA_PENDING":
        return False, "Invalid session state.", None

    user: User = session.user

    if not verify_totp_token(user.totp_secret, totp_token):
        return False, "Invalid or expired TOTP token.", None

    # ── Upgrade session ───────────────────────────────────────────────────
    session.state = "FULLY_AUTHENTICATED"
    session.expires_at = datetime.utcnow() + timedelta(hours=FULL_SESSION_TTL_HOURS)
    db.session.commit()

    return True, "MFA verified. Login complete.", {
        "session_token": session.token,
        "state": session.state,
        "user": user.username,
    }


def require_full_auth(token: str) -> Tuple[bool, Optional[User], str]:
    """
    Middleware helper: call at the top of any protected endpoint.

    Returns (ok, user, error_message)
    """
    session = get_session(token)
    if not session:
        return False, None, "Session not found or expired."
    if session.state != "FULLY_AUTHENTICATED":
        return False, None, "MFA verification required."
    return True, session.user, ""
