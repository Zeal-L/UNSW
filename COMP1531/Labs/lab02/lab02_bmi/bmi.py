weight = float(input("What is your weight in kg? "))
height = float(input("What is your height in m? "))
print("Your BMI is {}".format(round((weight/height**2), 1)))