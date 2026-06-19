import re


def detect_credit_card(text: str):
    """
    Detect credit/debit card numbers from text
    """

    pattern = r"\b(?:\d[ -]*?){13,16}\b"

    matches = re.findall(pattern, text)

    valid_cards = []

    for card in matches:
        cleaned_card = re.sub(r"[ -]", "", card)

        if 13 <= len(cleaned_card) <= 16:
            valid_cards.append(cleaned_card)

    if valid_cards:
        return {
            "type": "CREDIT_CARD",
            "count": len(valid_cards),
            "status": "DETECTED",
            "matches": valid_cards
        }

    return None
