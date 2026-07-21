import re

SECRET_PATTERNS = {
    "Generic Secret/Key": r"(?i)(api[_-]?key|secret|token|password|auth)\s*=\s*['\"]?([a-zA-Z0-9_\-.~+]{8,})['\"]?",
    "AWS Access Key ID": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "Private Key": r"-----BEGIN (RSA|EC|PGP|OPENSSH)? PRIVATE KEY-----"
}

def scan_file_for_secrets(file_path: str) -> list:
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, start=1):
                for rule_name, pattern in SECRET_PATTERNS.items():
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        findings.append({
                            "file": file_path,
                            "line": line_num,
                            "rule": rule_name,
                            "match_snippet": match.group(0)[:30] + "..."  # Truncate for display safety
                        })
    except Exception as e:
        findings.append({"file": file_path, "error": str(e)})
        
    return findings
