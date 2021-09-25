# items = ['a', 'b', 'c', 'd']

# for idx, item in enumerate(items):
#     print(f"{idx}: {item}")


# items = [(1, 'a'), (2, 'b'), (3, 'c')]

#?--------------------------------------------------

# # Tuples - Destructuring
# # Meh
# for item in items:
#     number = item[0]
#     char = item[1]
#     print(f"{number} {char}")

# # Good!
# for item in items:
#     number, char = item
#     print(f"{number} {char}")

# # Amazing
# for number, char in items:
#     print(f"{number} {char}")

#?--------------------------------------------------

# userData = [
#     {
#         'name' : 'Sally',
#         'age' : 18,
#         'height' : '186cm',
#     }, {
#         'name' : 'Bob',
#         'age' : 17,
#         'height' : '188cm',
#     },
# ]
# for user in userData:
#     print("Whole user: ", user)
#     for part in user:
#         print(f" {part} => {user[part]}")

#?--------------------------------------------------

# userData = {'name' : 'Sally','age' : 18, \
#             'height' : '186cm'}

# for user in userData.items():
#     print(user)
# print("====================")

# for user in userData.keys():
#     print(user)

# print("====================")
# for user in userData.values():
#     print(user)


#if __name__ == '__main__':

#?--------------------------------------------------

# import numpy as np

# a = np.array(42)
# b = np.array([1, 2, 3, 4, 5])
# c = np.array([[1, 2, 3], [4, 5, 6]])
# d = np.array([[[1, 2, 3], [4, 5, 6]], [[1, 2, 3], [4, 5, 6]]])

# # dimensions
# print(a.ndim)
# print(b.ndim)
# print(c.ndim)
# print(d.ndim)

# python -m virtualenv venv/
# source venv/Scripts/activate
# deactivate
# pip freeze > requirements.txt # Save modules
# pip install -r requirements.txt

#?--------------------------------------------------

# import sys

# def sqrt(x):
#     if x < 0:
#         raise Exception(f"Error, sqrt input {x} < 0")
#     return x**0.5

# if __name__ == '__main__':
#     print("Please enter a number: ",)
#     while True:
#         try:
#             inputNum = int(sys.stdin.readline())
#             print(sqrt(inputNum))
#             break
#         except Exception as e:
#             print(f"Error when inputting! {e}. Please try again:")

#?--------------------------------------------------

# import pytest

# def sqrt(x):
#     if x < 0:
#         raise ValueError(f"Input {x} is less than 0. Cannot sqrt a number < 0")
#     return x**0.5

# def test_sqrt_ok():
#     assert sqrt(1) == 1
#     assert sqrt(4) == 2
#     assert sqrt(9) == 3
#     assert sqrt(16) == 4

# def test_sqrt_bad():
#     with pytest.raises(Exception):
#         sqrt(-1)
#         sqrt(-2)
#         sqrt(-3)
#         sqrt(-4)
#         sqrt(-5)

#?--------------------------------------------------

