import re


def detect_phone(text: str):
    """
    Detect Indian phone numbers from text
    """

    pattern = r"\b(?:\+91[- ]?)?[6-9]\d{9}\b"

    matches = re.findall(pattern, text)

    if matches:
        return {
            "type": "PHONE_NUMBER",
            "count": len(matches),
            "status": "DETECTED",
            "matches": matches
        }

    return None
