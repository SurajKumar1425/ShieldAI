SAFE_KEYWORDS = [
    "example",
    "sample",
    "dummy",
    "test",
    "tutorial",
    "documentation",
    "how to",
    "create",
    "learn",
    "regex",
    "format"
]


DANGEROUS_KEYWORDS = [
    "real",
    "customer",
    "client",
    "production",
    "my account",
    "my password",
    "my api key",
    "secret"
]


def analyze_intent(text):

    text = text.lower()

    safe_context = any(
        keyword in text
        for keyword in SAFE_KEYWORDS
    )

    dangerous_context = any(
        keyword in text
        for keyword in DANGEROUS_KEYWORDS
    )

    return {
        "safe_context": safe_context,
        "dangerous_context": dangerous_context
    }
