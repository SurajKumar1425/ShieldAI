from core.detector import detect_sensitive_data


def test_email_detection():

    text = "Customer email is test@gmail.com"

    result = detect_sensitive_data(text)

    assert result[0]["type"] == "EMAIL"


def test_aadhaar_detection():

    text = "Aadhaar number is 1234 5678 9012"

    result = detect_sensitive_data(text)

    assert result[0]["type"] == "AADHAAR_NUMBER"


def test_safe_text():

    text = "How to learn Python programming"

    result = detect_sensitive_data(text)

    assert len(result) == 0


if __name__ == "__main__":

    print("Running Detector Tests...")

    test_email_detection()

    test_aadhaar_detection()

    test_safe_text()

    print("All Detector Tests Passed")
