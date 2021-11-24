## Lab02 - Exercise - Password (1 point)

1. Open `password.py` and have a look at the function stub.
2. In `password_test.py`, write at least 5 tests for the function. This should be 5 functions, each which test one conceptual case / scenario / input. Each test should have a name that explains what is being tested.
3. Run the tests, and they should fail.
4. Implement the `check_password` function so that your tests pass.

<details>
<summary>Hints</summary>

* The `.isupper()` method allows to to test whether a string is uppercase
* The `.islower()` method allows to to test whether a string is lowercase
* The `.isnumeric()` method allows to to test whether a string is a substring of `'0123456789'`
* You can find the number of characters in a string using `len('my string')`.

</details>