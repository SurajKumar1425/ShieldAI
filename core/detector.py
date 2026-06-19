import re


PATTERNS = {
    "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",

    "AWS_API_KEY": r"AKIA[0-9A-Z]{16}",

    "AADHAAR_NUMBER": r"\b\d{4}\s\d{4}\s\d{4}\b",

    "PAN_NUMBER": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",

    "INDIAN_PHONE": r"\+91\s?[6-9][0-9]{9}",

    "IFSC_CODE": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",

    "PASSWORD": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?.+['\"]?",

    "API_TOKEN": r"(?i)(token|secret|api_key)\s*[:=]\s*['\"]?.+['\"]?"
}


def detect_sensitive_data(text):

    findings = []

    for data_type, pattern in PATTERNS.items():

        matches = re.findall(
            pattern,
            text
        )

        if matches:
            findings.append({
                "type": data_type,
                "count": len(matches),
                "status": "DETECTED"
            })

    return findings
