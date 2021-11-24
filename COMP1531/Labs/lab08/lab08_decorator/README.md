## Lab08 - Exercise - Decorator (1 point)

Look at `decorator.py`. When you run it like the following:

```bash
python3 decorator.py CrocodileLikesStrawberries
```

The token `"CrocodileLikesStrawberries"` allows you to interact with the functions.

This code is OK, but there is repetition with the checks for `auth_token`.
We could pull this out into its own function, but what is even better design is to use a decorator.
Create an `authorise` decorator and use it with the refactored code given below.

If the provided token is invalid, an `Exception` should be raised by the `authorise` decorator.

```python
import sys

MESSAGE_LIST = []

@authorise
def get_messages():
    return MESSAGE_LIST

@authorise
def add_messages(msg):
    global MESSAGE_LIST
    MESSAGE_LIST.append(msg)

if __name__ == '__main__':
    auth_token = ""
    if len(sys.argv) == 2:
        auth_token = sys.argv[1]

    add_messages(auth_token, "Hello")
    add_messages(auth_token, "How")
    add_messages(auth_token, "Are")
    add_messages(auth_token, "You?")
    print(get_messages(auth_token))
```

You will also have to modify the code to ensure it is pylint compliant.
