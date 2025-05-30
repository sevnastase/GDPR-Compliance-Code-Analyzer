import re

def is_an_email(email):
    email_pattern = r'^([A-Z|a-z|0-9](\.|_){0,1})+[A-Z|a-z|0-9]\@([A-Z|a-z|0-9])+((\.){0,1}[A-Z|a-z|0-9]){2}\.[a-z]{2,3}$'
    return re.match (email_pattern, email) is not None

# Test Cases


# Example Usage
email_1 = "user@example.com"  # valid email
email_2 = "firstname.lastname@company.co.uk"  # Invalid hashtag
email_3 = "you.com"  # invalid email
email_4 = '@email.com'  # Invalid email

print(f"{email_3} is valid email: {is_an_email(email_1)}")
print(f"{email_4} is valid email: {is_an_email(email_2)}")
print(f"{email_3} is valid email: {is_an_email(email_3)}")
print(f"{email_4} is valid email: {is_an_email(email_4)}")