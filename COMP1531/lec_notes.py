items = ['a', 'b', 'c', 'd']

for idx, item in enumerate(items):
    print(f"{idx}: {item}")


items = [(1, 'a'), (2, 'b'), (3, 'c')]


# Tuples - Destructuring
# Meh
for item in items:
    number = item[0]
    char = item[1]
    print(f"{number} {char}")

# Good!
for item in items:
    number, char = item
    print(f"{number} {char}")

# Amazing
for number, char in items:
    print(f"{number} {char}")