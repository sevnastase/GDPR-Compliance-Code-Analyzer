#from shreyas

import logging
import requests
import smtplib

email = "user@example.com"
password = "supersecret"
ssn = "123-45-6789"
dob = "2000-01-01"

# Leak via print
print(email)
print(password)

# Leak via file write
with open("out.txt", "w") as f:
    f.write(ssn)

# Leak via database insert (simulated)
def insert_into_db(data):
    pass
insert_into_db(dob)

# Leak via cookie
class Response:
    def set_cookie(self, key, value):
        pass
response = Response()
response.set_cookie("user_email", email)

# Leak via logging
logging.info("User email: %s", email)
logging.error("Password: %s", password)

# Leak via HTTP request
requests.post("https://example.com/api", data={"ssn": ssn})

# Leak via email
smtp = smtplib.SMTP("localhost")
smtp.sendmail("from@example.com", "to@example.com", password)

# Leak via HTTP response
def get_user():
    return Response(email)