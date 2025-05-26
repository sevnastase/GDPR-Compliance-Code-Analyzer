from flask import jsonify

email = "user@example.com"
ssn = "123-45-6789"

# This should trigger isReturnedInJson
response = jsonify({"email": email, "ssn": ssn})