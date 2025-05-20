def hash_email(email):
    return hash(email)

secure_data = hash_email("user@example.com")