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
# HTTP

# from flask import Flask, send_file

# APP = Flask(__name__)

# @APP.route('/')
# def hello():
#     return "Hello World!"

# @APP.route('/cat')
# def get_cat():
#     address = "C:\\Users\\Zeal\\Pictures\\图片\\壁纸\\-klbw3Q5-erocZ1lT3cSxc-xc.jpg"
#     return send_file(address, mimetype="image/jpg")

# if __name__ == '__main__':
#     APP.run(port=1000)

#?--------------------------------------------------

# import json
# import requests

# if __name__ == '__main__':
#     # response = requests.get('http://localhost:2000/heroes')
#     # response_data = response.json()
#     # print(response_data)

#     response = requests.delete('http://localhost:2000/heroes/1')
#     response_data = response.json()
#     print(response_data)

#?--------------------------------------------------
#! Decorator

# def make_uppercase(fn):
# 	def wrapper(*args, **kwargs):
# 		return fn(*args, **kwargs).upper()
# 	return wrapper

# @make_uppercase
# def get_first_name():
# 	return "Hayden"

# @make_uppercase
# def get_last_name():
# 	return "Smith"

# if __name__ == '__main__':
#     print(get_first_name())
#     print(get_last_name())

#?--------------------------------------------------
#! Decorator More

# class Message:
# 	def __init__(self, id, text):
# 		self.id = id
# 		self.text = text

# messages = [
# 	Message(1, "Hello"),
# 	Message(2, "How are you?"),
# ]

# def get_message_by_id(id):
# 	return [m for m in messages if m.id == id][0]

# def message_id_to_obj(function):
# 	def wrapper(*args, **kwargs):
# 		argsList = list(args)
# 		argsList[0] = get_message_by_id(argsList[0])
# 		args = tuple(argsList)
# 		return function(*args, **kwargs)
# 	return wrapper

# @message_id_to_obj
# def printMessage(message):
# 	print(message.text)

# if __name__ == '__main__':
# 	printMessage(1)

#?--------------------------------------------------

# import threading

# def hello():
#     print("hello, Timer")

# if __name__ == '__main__':
#     t = threading.Timer(2.0, hello)
#     t.start()
#     print('Starting')

#?--------------------------------------------------

