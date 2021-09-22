# items = ['a', 'b', 'c', 'd']

# for idx, item in enumerate(items):
#     print(f"{idx}: {item}")


# items = [(1, 'a'), (2, 'b'), (3, 'c')]


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


