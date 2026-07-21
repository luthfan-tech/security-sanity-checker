import re
from collections import defaultdict

# Matches patterns like "Failed password for root from 192.168.1.50"
FAILED_LOGIN_PATTERN = r"(?i)failed (password|login) .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

def parse_failed_logins(log_file_path: str, threshold: int = 3) -> list:
    ip_counts = defaultdict(int)
    
    try:
        with open(log_file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                match = re.search(FAILED_LOGIN_PATTERN, line)
                if match:
                    ip = match.group(2)
                    ip_counts[ip] += 1
    except Exception as e:
        return [{"error": f"Failed to read log file: {str(e)}"}]

    alerts = []
    for ip, count in ip_counts.items():
        if count >= threshold:
            alerts.append({
                "source_ip": ip,
                "failed_attempts": count,
                "status": "SUSPICIOUS_BRUTE_FORCE_PATTERN"
            })
            
    return alerts
