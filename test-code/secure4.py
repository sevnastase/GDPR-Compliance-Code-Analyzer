def hash_email(ssn):
    return hash(ssn)

secure_data = hash_email("123-45-6789")