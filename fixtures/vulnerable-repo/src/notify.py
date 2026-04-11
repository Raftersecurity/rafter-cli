# Notification service — INTENTIONAL FAKE SECRETS for fixture testing
import requests

SLACK_WEBHOOK = "https://hooks.example.com/services/T0FAKEEX/B0FAKEEX/FAKE1cD2eF3gH4iJ5kL6mN7"

def send_alert(message):
    requests.post(SLACK_WEBHOOK, json={"text": message})
