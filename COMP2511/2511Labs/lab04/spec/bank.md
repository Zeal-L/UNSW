## Lab 04 - Exercise - The Bank's Contract 💰

> ℹ️ You will need to make a **Private** (set to Course Staff can view only) Blog Post on WebCMS for this activity. Put your answers to the questions inside it.

Consider a simple Bank system that allows for customers to have accounts. The customers can make deposits and withdrawals, and in this simplified system, an account balance is never allowed to go below 0. 

Inside `src/banking`, create a `BankAccount` class for maintaining a customer's bank balance.
  * Each bank account should have a current balance and methods implementing deposits and withdrawals.
  * Money can only be withdrawn from an account if there are sufficient funds.

In the JavaDoc for the methods, define preconditions and postconditions for the methods.

Then, create a subclass of `BankAccount` called `LoggedBankAccount`, also with the preconditions and postconditions articulated. 
  * Every deposit and withdrawal must make a log of the action.

Inside your blog post, answer the following questions in a few sentences:

* Explain why the code is consistent with the preconditions and postconditions.
* Explain why *balance >= 0* is a class invariant for both classes.
* Are your class definitions consistent with the Liskov Substitution Principle?
