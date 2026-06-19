import re


def detect_email(text: str):
    """
    Detect email addresses from text
    """

    pattern = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"

    matches = re.findall(pattern, text)

    if matches:
        return {
            "type": "EMAIL_ADDRESS",
            "count": len(matches),
            "status": "DETECTED",
            "matches": matches
        }

    return None
