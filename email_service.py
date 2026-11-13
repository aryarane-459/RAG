import os
import smtplib
from email.message import EmailMessage

from dotenv import load_dotenv

load_dotenv()

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")


def send_otp_email(recipient_email: str, otp: str) -> bool:
    """
    Send an OTP verification email.
    Returns True if the email is sent successfully.
    Raises an exception if SMTP configuration or delivery fails.
    """

    if not SMTP_EMAIL or not SMTP_PASSWORD:
        raise RuntimeError(
            "SMTP_EMAIL or SMTP_PASSWORD is missing from .env"
        )

    message = EmailMessage()
    message["Subject"] = "Your Email Verification OTP"
    message["From"] = SMTP_EMAIL
    message["To"] = recipient_email

    message.set_content(
        f"""Hello,

Your email verification OTP is: {otp}

This OTP is valid for 5 minutes.
Do not share this code with anyone.

If you did not request this code, you can ignore this email.

Regards,
Document RAG Team
"""
    )

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.send_message(message)

    return True
