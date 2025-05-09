import bcrypt


def hash_password(
    password: str
) -> bytes:
    salt = bcrypt.gensalt()
    password_bytes: bytes = password.encode()
    return bcrypt.hashpw(password_bytes, salt)

def validate_password(
    password: str,
    password_hash: bytes
) -> bool:
    return bcrypt.checkpw(
        password=password.encode(),
        hashed_password=password_hash
    )