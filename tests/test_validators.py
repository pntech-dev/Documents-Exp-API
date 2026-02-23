import pytest
from fastapi import HTTPException
from utils.validators import validate_password, validate_file_extension

# ---------------------------------------------------------------------------
# Password Validation Tests
# ---------------------------------------------------------------------------

def test_validate_password_valid():
    """Test valid passwords."""
    assert validate_password("StrongPass1") == "StrongPass1"
    assert validate_password("Another1Valid!") == "Another1Valid!"

def test_validate_password_too_short():
    """Test password length validation."""
    with pytest.raises(ValueError, match="at least 8 characters"):
        validate_password("Short1A")

def test_validate_password_whitespace():
    """Test whitespace validation."""
    with pytest.raises(ValueError, match="whitespace"):
        validate_password("Space 1A")

def test_validate_password_no_digit():
    """Test digit requirement."""
    with pytest.raises(ValueError, match="at least one digit"):
        validate_password("NoDigitA")

def test_validate_password_no_letter():
    """Test letter requirement."""
    with pytest.raises(ValueError, match="at least one letter"):
        validate_password("12345678")

def test_validate_password_no_uppercase():
    """Test uppercase letter requirement."""
    with pytest.raises(ValueError, match="at least one uppercase"):
        validate_password("lower1case")

# ---------------------------------------------------------------------------
# File Extension Validation Tests
# ---------------------------------------------------------------------------

def test_validate_file_extension_valid():
    """Test allowed file extensions."""
    validate_file_extension("document.pdf")
    validate_file_extension("image.png")
    validate_file_extension("archive.zip")
    validate_file_extension("no_extension")
    validate_file_extension("")
    validate_file_extension(None)

def test_validate_file_extension_blocked():
    """Test blocked file extensions."""
    blocked_extensions = ["exe", "bat", "sh", "py", "dll", "EXE"]
    for ext in blocked_extensions:
        with pytest.raises(HTTPException) as exc:
            validate_file_extension(f"malicious.{ext}")
        assert exc.value.status_code == 400
        assert "not allowed" in exc.value.detail