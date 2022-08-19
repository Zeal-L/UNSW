## Lab 02 - Choice Exercise - Pineapple on Piazza 🍕

Welcome back to Piazza (even though Ed is a much better forum). This week we're going to finish off our implementation. We are going to make `Post` its own class, and implement functions which raise exceptions. If you didn't complete the Piazza challenge exercise last week then that's OK!

Updated requirements:

**`Post`**

* A `Post` is created by a particular author;
* The author is able to edit the content, but other users cannot;
* Any user should be able to bump the upvotes, but only once per user.

**`Thread`**

* A `Thread` is created with a title, and a first post;
* The owner of the thread is the author of the first post;
* Any new user can add a new post to the thread;
* The thread owner can edit the title and tags, but other users cannot.

**`PiazzaForum`**

* The `Forum` contains a list of threads;
* Users can search for threads by tag;
* Users can search for posts by author.

Once again, there are a series of function stubs provided for you to implement with instructions in the JavaDoc.

There is also a class defined called `PermissionDeniedException` which you should `raise` whenever a user tries to perform an action (e.g. delete someone else's post) that they are not allowed to perform. You can throw (equivalent of `raise` in Python) this exception using `throw new PermissionDeniedException()`.
