import re


def detect_pan(text: str):
    """
    Detect PAN card numbers from text
    Format: ABCDE1234F
    """

    pattern = r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"

    matches = re.findall(pattern, text)

    if matches:
        return {
            "type": "PAN_CARD",
            "count": len(matches),
            "status": "DETECTED",
            "matches": matches
        }

    return None
