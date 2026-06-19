import re


def detect_api_key(text: str):
    """
    Detect API keys and secrets
    """

    patterns = [
        r"sk-[A-Za-z0-9]{20,}",
        r"AIza[0-9A-Za-z\-_]{35}",
        r"ghp_[A-Za-z0-9]{36}",
    ]

    matches = []

    for pattern in patterns:
        matches.extend(re.findall(pattern, text))

    if matches:
        return {
            "type": "API_KEY_OR_SECRET",
            "count": len(matches),
            "status": "DETECTED",
            "matches": matches
        }

    return None
