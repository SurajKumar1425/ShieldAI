import re


def detect_email(text: str):
    """
    Detect email addresses
    """

    pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

    matches = re.findall(pattern, text)

    if matches:
        return {
            "type": "EMAIL_ADDRESS",
            "count": len(matches),
            "status": "DETECTED",
            "matches": matches
        }

    return None
