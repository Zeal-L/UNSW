# 103: Introduction to the Art of Testing

An oft overlooked and perhaps undervalued skill is the ability to write readable, maintainable, and scalable tests.

The purpose of this exercise is to consider the two main test types and to practise the art and skill of writing tests _before_ implementation.

Consider:
1. What is a **Unit test**?
2. What is an **Integration test**?
3. How do unit tests and integration tests differ? Where would you use one over the other?

In `src/setdiff.h` there is a documentation for a function that removes elements in one vector from another. In the provided test stub in `src/setdiff.test.cpp`, write **three** or more _unit tests_ for this function. Considerations include:
- a test for invalid input
- a test for an _edge_ case
- a test for the average use case

When you are happy with the tests, implement the function in `src/setdiff.cpp` so that your tests pass.

Was it easier or harder to write the tests before implementation?
