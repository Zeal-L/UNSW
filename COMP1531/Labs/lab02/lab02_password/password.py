def check_numeric(password):
    for i in password:
        if (i.isnumeric() == True):
            return True
    return False

def check_supper(password):
    for i in password:
        if (i.isupper() == True):
            return True
    return False

def check_lower(password):
    for i in password:
        if (i.islower() == True):
            return True
    return False

def check_password(password):
    '''
    Takes in a password, and returns a string based on the strength of that password.

    The returned value should be:
    * "Strong password", if at least 12 characters, contains at least one number, at least one uppercase letter, at least one lowercase letter.
    * "Moderate password", if at least 8 characters, contains at least one number.
    * "Poor password", for anything else
    * "Horrible password", if the user enters "password", "iloveyou", or "123456"
    '''
    if (password == "password" or
        password == "iloveyou" or
        password == "123456"):
        return "Horrible password"
    elif (len(password) >= 12 and check_numeric(password) and
        check_supper(password) and check_lower(password)):
        return "Strong password"
    elif (len(password) >= 8 and
        check_numeric(password)):
        return "Moderate password"
    else:
        return "Poor password"

if __name__ == '__main__':
    print(check_password("123"))
    # "Poor password"
