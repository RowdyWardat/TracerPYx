from demo_auth import weak_verify
def authenticate(user, password):
    callback = getattr(weak_verify, "__call__")
    return callback(user, password)
