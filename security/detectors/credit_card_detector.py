import re


def detect_credit_card(text: str):
    """
    Detect credit card numbers
    """

    pattern = r"\b(?:\d[ -]*?){13,16}\b"

    matches = re.findall(pattern, text)

    if matches:
        return {
            "type": "CREDIT_CARD",
            "count": len(matches),
            "status": "DETECTED",
            "matches": matches
        }

    return None
