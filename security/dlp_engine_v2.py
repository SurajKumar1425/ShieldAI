from security.detectors.pan_detector import detect_pan
from security.detectors.email_detector import detect_email
from security.detectors.phone_detector import detect_phone
from security.detectors.credit_card_detector import detect_credit_card
from security.detectors.api_key_detector import detect_api_keys
from security.detectors.password_detector import detect_password


def scan_sensitive_data(text: str):
    """
    ShieldAI v2 Advanced DLP Scanner
    Runs all sensitive data detectors
    """

    detectors = [
        detect_pan,
        detect_email,
        detect_phone,
        detect_credit_card,
        detect_api_keys,
        detect_password
    ]

    detections = []

    for detector in detectors:
        result = detector(text)

        if result:
            detections.append(result)

    return {
        "total_detections": len(detections),
        "detections": detections
    }
