import boto3

from core.config import settings


def send_otp_email(
    receiver_email: str,
    otp_code: str
):

    try:

        ses_client = boto3.client(
            "ses",
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )


        subject = (
            "ShieldAI Email Verification Code"
        )


        body = f"""
Hello,

Welcome to ShieldAI Enterprise Security Platform.


Your verification code is:

{otp_code}


Security Notice:

- This OTP will expire in 5 minutes.
- Never share this code with anyone.
- ShieldAI employees will never ask for your OTP.


If you did not create this account,
please ignore this email.


Regards,

ShieldAI Security Team
"""


        ses_client.send_email(

            Source=settings.AWS_SES_FROM_EMAIL,

            Destination={
                "ToAddresses": [
                    receiver_email
                ]
            },


            Message={

                "Subject": {
                    "Data": subject
                },


                "Body": {

                    "Text": {
                        "Data": body
                    }

                }

            }

        )


        return True


    except Exception as error:

        print(
            "ShieldAI Email Error:",
            error
        )

        return False
