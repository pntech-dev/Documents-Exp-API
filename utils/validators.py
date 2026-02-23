from fastapi import HTTPException


BLOCKED_EXTENSIONS = {
    "exe", "dll", "bat", "cmd", "sh", "js", "vbs", "scr", 
    "com", "pif", "jar", "app", "php", "pl", "py", "rb", 
    "asp", "aspx", "jsp", "cgi", "ps1", "reg", "msi", "wsf",
    "hta", "cpl", "msc", "lnk", "inf"
}


def validate_password(password: str) -> str:
        """
        Validates the password against security policies.

        Checks if the password meets the following requirements:
        - Minimum length of 8 characters.
        - No whitespace characters.
        - At least one digit.
        - At least one letter.
        - At least one uppercase letter.

        Args:
            password (str): The password to validate.

        Returns:
            str: The password if it is valid.

        Raises:
            ValueError: If the password does not meet the requirements.
        """
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")

        if any(char.isspace() for char in password):
            raise ValueError("Password cannot contain whitespace characters")
        
        if not any(char.isdigit() for char in password):
            raise ValueError("Password must contain at least one digit")

        if not any(char.isalpha() for char in password):
            raise ValueError("Password must contain at least one letter")
        
        if not any(char.isupper() for char in password):
            raise ValueError("Password must contain at least one uppercase letter")

        return password


def validate_file_extension(filename: str) -> None:
    """
    Validates that the file extension is not in the blocked list.

    Args:
        filename (str): The name of the file.

    Raises:
        HTTPException: If the file type is not allowed.
    """
    if not filename:
        return
        
    parts = filename.split(".")
    if len(parts) < 2:
        return # No extension
        
    ext = parts[-1].lower()
    
    if ext in BLOCKED_EXTENSIONS:
        raise HTTPException(
            status_code=400, 
            detail=f"File type '{ext}' is not allowed for security reasons."
        )