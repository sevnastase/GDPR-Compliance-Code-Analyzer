import requests

email = "user@example.com"
ssn = "123-45-6789"

# This should trigger isSentViaHttp
requests.post("https://example.com/submit", data={"email": email, "ssn": ssn})