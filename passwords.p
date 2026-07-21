import re

COMMON_WEAK = {"password", "123456", "12345678", "admin", "welcome", "qwerty"}

def check_password_strength(password: str) -> dict:
    issues = []
    
    if len(password) < 8:
        issues.append("Too short (less than 8 characters)")
    if password.lower() in COMMON_WEAK:
        issues.append("Matches high-risk weak password dictionary")
    if not re.search(r"[A-Z]", password):
        issues.append("Missing uppercase letter")
    if not re.search(r"[a-z]", password):
        issues.append("Missing lowercase letter")
    if not re.search(r"\d", password):
        issues.append("Missing digit")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        issues.append("Missing special character")

    status = "WEAK" if len(issues) >= 2 else ("MEDIUM" if issues else "STRONG")
    
    return {
        "input": password,
        "status": status,
        "issues": issues
    }
