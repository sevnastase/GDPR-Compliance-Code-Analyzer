email_1 = "user@example.com"  # valid email
email_2 = "firstname.lastname@company.co.uk"  # Invalid hashtag
email_3 = "you.com"  # invalid email
email_4 = '@email.com'  # Invalid email
print(f"{email_3} is valid email: {is_an_email(email_1)}")