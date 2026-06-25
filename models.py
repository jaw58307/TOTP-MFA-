"""
models.py - Database models for TOTP MFA system
"""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    # TOTP / MFA fields
    totp_secret   = db.Column(db.String(64), nullable=True)   # base32 secret
    mfa_enabled   = db.Column(db.Boolean, default=False)
    mfa_verified  = db.Column(db.Boolean, default=False)      # has user confirmed enrollment?

    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.username} mfa={self.mfa_enabled}>"


class Session(db.Model):
    """Tracks login sessions with a two-stage MFA state machine."""
    __tablename__ = "sessions"

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    token      = db.Column(db.String(128), unique=True, nullable=False)

    # State machine:  PASSWORD_OK  →  MFA_PENDING  →  FULLY_AUTHENTICATED
    state      = db.Column(db.String(30), default="PASSWORD_OK")

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active  = db.Column(db.Boolean, default=True)

    user = db.relationship("User", backref="sessions")

    def __repr__(self):
        return f"<Session user={self.user_id} state={self.state}>"
