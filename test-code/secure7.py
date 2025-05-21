def hash_email(email):
    return hash(email)

email = "user@example.com"
url = "https://example.com/profile?email=" + str(hash_email(email))