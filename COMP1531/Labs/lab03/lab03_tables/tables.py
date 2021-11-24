from random import randint
x = randint(2, 12)
y = randint(2, 12)
while True:
    result = int(input(f"What is {x} x {y}? "))
    if result == x * y:
        print("Correct!")
        break
    print("Incorrect - try again.")
