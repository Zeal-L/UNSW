import sys
MAX_INT = sys.maxsize

def drykiss(my_list):
    # Default maximum number
    my_min = MAX_INT
    for i in range(0, 5):
        if my_list[i] < my_min:
            my_min = my_list[i]

    product = 1
    for i in range(0, 4):
        product = product * my_list[i]
    first_4 = product

    product = 1
    for i in range(1, 5):
        product = product * my_list[i]
    last_4 = product

    # Make variable names meaningful
    return (my_min, first_4, last_4)

if __name__ == '__main__':

    # Compress the code just put the type
    # conversion directly in front of the input
    a = int(input("Enter a: "))
    b = int(input("Enter b: "))
    c = int(input("Enter c: "))
    d = int(input("Enter d: "))
    e = int(input("Enter e: "))
    print(sys.maxsize)
    my_list = [a, b, c, d, e]
    result = drykiss(my_list)
    print("Minimum: " + str(result[0]))
    print("Product of first 4 numbers: ")
    print(f"  {result[1]}")
    print("Product of last 4 numbers")
    print(f"  {result[2]}")
