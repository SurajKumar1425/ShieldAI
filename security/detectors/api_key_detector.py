import re


def detect_api_keys(text: str):
    """
    Detect API keys and secret tokens
    """

    patterns = [
        # OpenAI API Key
        r"sk-[A-Za-z0-9]{20,}",

        # Google API Key
        r"AIza[0-9A-Za-z\-_]{35}",

        # AWS Access Key
        r"AKIA[0-9A-Z]{16}",

        # GitHub Personal Access Token
        r"ghp_[A-Za-z0-9]{36}",

        # Generic API Keys
        r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*[A-Za-z0-9_\-]{8,}"
    ]

    detected_keys = []

    for pattern in patterns:
        matches = re.findall(pattern, text)
        detected_keys.extend(matches)

    if detected_keys:
        return {
            "type": "API_KEY_OR_SECRET",
            "count": len(detected_keys),
            "status": "DETECTED",
            "matches": detected_keys
        }

    return None
