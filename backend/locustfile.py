from locust import HttpUser, task, between
import random

SAMPLE_MESSAGES = [
    "GCash: Your account has been accessed. Verify: http://gcash-verify.com",
    "Hi mom, running late for dinner",
    "Congratulations! You won a prize, claim now",
]

class BantayBaitUser(HttpUser):
    wait_time = between(1, 3)

    @task
    def detect(self):
        self.client.post("/api/v1/detect", json={
            "text": random.choice(SAMPLE_MESSAGES),
            "lang": "auto"
        })