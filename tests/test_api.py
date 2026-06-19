import requests


BASE_URL = "http://localhost:8000"


def test_scan_api():

    payload = {
        "user_id": "employee_001",
        "company": "ABC_BANK",
        "company_type": "BANK",
        "text": (
            "Customer Aadhaar number "
            "is 1234 5678 9012"
        )
    }

    response = requests.post(
        f"{BASE_URL}/scan",
        json=payload
    )

    print(
        "Scan API Result:"
    )

    print(
        response.json()
    )


def test_login_api():

    payload = {
        "email": "admin@abc_bank.com",
        "password": "Admin@123"
    }

    response = requests.post(
        f"{BASE_URL}/login",
        json=payload
    )

    print(
        "Login API Result:"
    )

    print(
        response.json()
    )


if __name__ == "__main__":

    print(
        "Starting ShieldAI API Tests..."
    )

    test_scan_api()

    print("-" * 50)

    test_login_api()
