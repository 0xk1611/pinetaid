"""
PiNetAid – auth.py
Simple credential store with bcrypt hashing.
No database needed for auth; credentials live in a local JSON file.
"""

import json
import os
import logging
import secrets
from functools import wraps

import bcrypt
from flask import session, redirect, url_for, request

logger = logging.getLogger("pinetaid.auth")

CREDENTIALS_FILE = os.path.join(os.path.dirname(__file__), "data", "credentials.json")


# ─── Credentials File ────────────────────────────────────────────────────────

def _load_credentials() -> dict:
    if os.path.isfile(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as f:
            return json.load(f)
    return {}


def _save_credentials(creds: dict) -> None:
    os.makedirs(os.path.dirname(CREDENTIALS_FILE), exist_ok=True)
    with open(CREDENTIALS_FILE, "w") as f:
        json.dump(creds, f, indent=2)


# ─── User Management ─────────────────────────────────────────────────────────

def create_user(username: str, password: str) -> None:
    """Hash and store a new user."""
    creds = _load_credentials()
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    creds[username] = hashed
    _save_credentials(creds)
    logger.info(f"User '{username}' created.")


def verify_user(username: str, password: str) -> bool:
    """Return True if username/password match stored hash."""
    creds = _load_credentials()
    hashed = creds.get(username)
    if not hashed:
        return False
    return bcrypt.checkpw(password.encode(), hashed.encode())


def user_exists() -> bool:
    """Return True if at least one user is configured."""
    return bool(_load_credentials())


# ─── Flask Decorators ────────────────────────────────────────────────────────

def login_required(f):
    """Redirect to login page if the user is not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def generate_secret_key() -> str:
    """Generate a cryptographically secure Flask secret key."""
    return secrets.token_hex(32)
