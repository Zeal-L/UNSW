income = float(input("Enter your income: "))

if (income >= 18201 and income <= 37000):
    income = (0.19 * (income - 18200))
elif (income >= 37001 and income <= 87000):
    income = (3572 + 0.325 * (income - 37000))
elif (income >= 87001 and income <= 180000):
    income = (19822 + 0.37 * (income - 87000))
elif (income >= 180001):
    income = (54232 + 0.45 * (income - 180000))

print("The estimated tax on your income is ${:,}".format(round(income, 2)))