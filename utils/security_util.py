import secrets
import hashlib

from random import randint
from passlib.context import CryptContext


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


"""=== Password ==="""

def hash_password(password: str) -> str:
    """
    Returns the hash string for the passed password.

    Args:
        password (str): The password to be hashed.

    Returns:
        str: The hashed password.
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Checks the transmitted password against the transmitted hash.
    Returns True if the passwords match, otherwise False.

    Args:
        plain_password (str): The password to be verified.
        hashed_password (str): The hash of the password.

    Returns:
        bool: True if the passwords match, otherwise False.
    """
    return pwd_context.verify(plain_password, hashed_password)



"""=== Code ==="""

def generate_verification_code() -> dict[str, str]:
    """
    Generates the verification code and its hash.

    Returns:
        dict(str, str): A dictionary containing the verification code and its hash.
    """

    code = randint(100000, 999999)
    code_hash = pwd_context.hash(str(code))

    return {"code": str(code), "code_hash": code_hash}



"""=== Token ==="""

def create_reset_token(nbytes: int) -> str:
    """
    Return a random URL-safe text string, in Base64 encoding.

    Args:
        nbytes (int): The number of bytes to generate.

    Returns:
        str: A random URL-safe text string.
    """
    return secrets.token_urlsafe(nbytes=nbytes)


def hash_token(token: str) -> str:
    """
    The function hashes the passed token into a SHA256 hash.

    Args:
        token (str): The token to be hashed.

    Returns:
        str: The hashed token.

    """
    return hashlib.sha256(token.encode('utf-8')).hexdigest()