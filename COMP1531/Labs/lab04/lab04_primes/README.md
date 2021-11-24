## Lab04 - Exercise - Primes (2 points)

In this task we will complete a function function `factors()` in `primes.py` that factorises a number into its prime factors.
The prime factors of a number are all of the prime numbers that together multiply to the original number.

<img src='https://www.mathsisfun.com/numbers/images/factor-tree-48.svg' />

For example, the number `10` has prime factors `[2, 5]` as `2 * 5 = 10`. The number 12 has prime factors `[3, 2, 2]` as `3 * 2 * 2 = 12`.

See the [documentation](https://en.wikipedia.org/wiki/Table_of_prime_factors) for more details.

Firstly, write a series of failing tests for your `factors` function in a file `primes_test.py`. Ensure your tests have 100% coverage.
Then implement the function. Ensure your code is pylint compliant.

Edge cases:
* `factors(1) == factors(0) == []`
