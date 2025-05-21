def hash_email(email):
    return hash(email)

url = "https://example.com/profile?email=" + hash_email(email)