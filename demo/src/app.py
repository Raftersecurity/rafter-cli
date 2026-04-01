# Demo Python app — INTENTIONAL FAKE SECRETS for rafter demo

import os

# Hardcoded credentials (bad practice — rafter catches these)
GOOGLE_API_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv"
TWILIO_AUTH_TOKEN = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
NPM_TOKEN = "npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"

# Private key embedded in source (critical finding)
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aFDrBz9vFqU5xTL0TLnPJqFMOgXK7CmGdL5YEQF5GnNFm2X7aSTFKWH4EXAMPLE
-----END RSA PRIVATE KEY-----"""


def connect_to_database():
    """Uses hardcoded connection string — rafter catches this."""
    conn_string = "postgresql://root:hunter2@prod-db.company.com:5432/users"
    return conn_string


def send_notification():
    """Uses hardcoded Slack webhook — rafter catches this."""
    webhook = "https://hooks.slack.example/services/T01234567/B01234567/abcdefghijklmnopqrstuvwx"
    return webhook
