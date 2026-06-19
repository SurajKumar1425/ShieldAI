import re


def detect_password(text: str):
    """
    Detect passwords and credentials in text
    """

    patterns = [
        # password = something
        r"(?i)(password|passwd|pwd)\s*[:=]\s*[\S]+",

        # common credential formats
        r"(?i)(username|user|login)\s*[:=]\s*[\w@.-]+\s+(password|pass|pwd)\s*[:=]\s*[\S]+"
    ]

    detected_passwords = []

    for pattern in patterns:
        matches = re.findall(pattern, text)

        for match in matches:
            if isinstance(match, tuple):
                detected_passwords.append("Credential pair detected")
            else:
                detected_passwords.append(match)

    if detected_passwords:
        return {
            "type": "PASSWORD_OR_CREDENTIAL",
            "count": len(detected_passwords),
            "status": "DETECTED",
            "matches": detected_passwords
        }

    return None
