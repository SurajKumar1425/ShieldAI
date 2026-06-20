import os


class Settings:

    JWT_SECRET_KEY = os.getenv(
        "JWT_SECRET_KEY",
        "CHANGE_THIS_SECRET"
    )


    DATABASE_NAME = os.getenv(
        "DATABASE_NAME",
        "shieldai.db"
    )


    EMAIL_PROVIDER = os.getenv(
        "EMAIL_PROVIDER",
        "AWS_SES"
    )


    AWS_ACCESS_KEY_ID = os.getenv(
        "AWS_ACCESS_KEY_ID"
    )


    AWS_SECRET_ACCESS_KEY = os.getenv(
        "AWS_SECRET_ACCESS_KEY"
    )


    AWS_REGION = os.getenv(
        "AWS_REGION",
        "ap-south-1"
    )


    AWS_SES_FROM_EMAIL = os.getenv(
        "AWS_SES_FROM_EMAIL"
    )


settings = Settings()
