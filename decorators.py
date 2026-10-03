from functools import wraps
from flask import session, redirect, url_for, abort
from auth import get_session_user


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_session_user(session.get("sid"))
        if user is None:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = get_session_user(session.get("sid"))
            if user is None:
                return redirect(url_for("login"))
            if user["role"] != role:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator