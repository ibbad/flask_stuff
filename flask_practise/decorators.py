from functools import wraps
from flask import abort
from flask.ext.login import current_user
from .models import Permission


def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwrags):
            if not current_user.can(permission):
                abort(403)   # Forbidden HTTP error.
            return f(*args, **kwrags)
        return decorated_function
    return decorator


def admin_required(f):
    return permission_required(Permission.ADMINISTER)(f)
