print("Pick a number between 1 and 100 (inclusive)")
exit = 0
lo = 1
hi = 100

while (exit == 0):
    guess = (hi + lo) // 2
    print(f"My guess is: {guess}")
    print("Is my guess too low (L), too high (H), or correct (C)?")
    response = input()
    if (response == "C"):
        print("Got it!", end = '')
        exit = 1
    elif (response == "H"):
        hi = guess - 1
    elif (response == "L"):
        lo = guess

