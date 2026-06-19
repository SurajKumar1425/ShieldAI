import re


def detect_password(text: str):
    """
    Detect passwords and credentials
    """

    patterns = [
        r"(?i)password\s*[:=]\s*\S+",
        r"(?i)passwd\s*[:=]\s*\S+",
        r"(?i)secret\s*[:=]\s*\S+",
        r"(?i)token\s*[:=]\s*\S+"
    ]

    matches = []

    for pattern in patterns:
        matches.extend(re.findall(pattern, text))

    if matches:
        return {
            "type": "PASSWORD_OR_CREDENTIAL",
            "count": len(matches),
            "status": "DETECTED",
            "matches": matches
        }

    return None
