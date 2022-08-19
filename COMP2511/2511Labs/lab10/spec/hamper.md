## Lab 10 - Revision Exercise - Hamper

Inside `src/main/unsw/hamper`, the interface `Hamper<E>` is for hampers that can handle elements of a generic type E. A hamper is similar to a set but allows for duplicate elements. A "hamper" in real life is a basket of gifts full of lots of nice things, e.g. fruits, chocolates, toys, etc...

Complete all methods marked TODO in `ArrayListItemHamper`, `CreativeHamper` and `FruitHamper`. The class `ArrayListItemHamper` uses an `ArrayList` of `Count<E>` to track the count of each element. Pay careful attention to the contract and documentation in `Hamper`, as well as the invariants in `ArrayListItemHamper`, `CreativeHamper`, and `FruitHamper` to make sure your implementation is correct. Make sure that your solution successfully passes the tests in `TestHamper`.

`CreativeHamper` is a hamper for which the price of the hamper is $10 more than the sum of the prices of the items inside it. A `CreativeHamper` which contains 5 or more items, must have at least 2 toy cars (at least 1 must be a premium toy car), and at least 2 fruits. When adding items to a `CreativeHamper`, if this condition cannot be adhered to, the items should not be added.

`FruitHamper` is a hamper of fruits for which the price of the hamper is 25% more than the sum of the prices of the fruits inside it (if the result of this is not an integer, the result should be rounded up to the nearest dollar). A `FruitHamper` which contains 6 or more fruits, must have at least 2 avocados, and at least 2 apples. When adding items to a `FruitHamper`, if this condition cannot be adhered to, the items should not be added.

Note that all currency values in this question and the starter code are in Australian dollars.

The tests used in automarking will be much more extensive than the JUnit tests provided in the dryrun and starter code. Thus, you should test your code thoroughly according to the details in this specification and the requirements/conditions outlined in the starter code.

You should not rely on any modifications to code other than in the files `ArrayListItemHamper.java`, `CreativeHamper.java` and `FruitHamper.java`

Note that, for your implementation of the `sum` method in `ArrayListItemHamper`, `FruitHamper`, and `CreativeHamper`, it is acceptable to create a new `ArrayListItemHamper` to contain the elements from the summation and return this.

