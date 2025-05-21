try:
    raise ValueError("Invalid input")
except ValueError as e:
    print(e)