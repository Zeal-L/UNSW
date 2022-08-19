## Lab 05 - Core Exercise - SSO

> ℹ️ You will need to make a **Private** (set to Course Staff can view only) Blog Post on WebCMS for this activity. Put your answers to the questions inside it.

| 💡 *To receive full marks in this exercise you do not need to complete all core parts* (up to Task 6). We will assess you on your ability to understand the code, how the components interact, make changes to improve the design and problem-solve along the way as opposed to the number of tasks you completed. This all should be documented in your blog post. Set aside a few hours (around 4-5 for most students) to work on the problem. Stop once you reach your allocated time and make sure to document how long you spent on each section. |
| --- |

<details>
<summary>
Copy this template into your blog.
</summary>

```
Task 1

Q1: Why do we need authentication for applications such as gmail/myunsw/facebook? 

<your answer here>

Task 2

<note down what you modified to implement caching>

Task 3

Q2: What code smells are present in the above code? How does this entail that the code does not adhere to the open-closed principle?

<your answer here>

Refactoring for Part A

<your refactoring steps here>

Q3: Explain why this logic doesn't adhere to the Open-Closed principle.

<your answer here>

Refactoring for Part B

<your refactoring steps here>

Task 4

Q4: What are the different States present in this problem? What are the different actions/transitions that are common to each state? What occurs on each action, relative to each state? This will form the basis for your use of the State pattern. You are welcome to make a State Transition Table if you like.

Q4: Will this be an interface or an abstract class? Why?

Task 4 Refactoring

<Your refactoring steps here>

Task 5

Q5: Identify the different 'strategies' present in this scenario.

Q6: Explain where and how the dynamic transitions between strategies in this context occur. How is this differently abstracted from other examples of the Strategy Pattern you have seen, for example the Restaurant system in the Week 5 Tutorial?

Task 6

Q7: What is the observing entity/entities in this case? What entity/entities are being observed?

Q8: How will you implement notification, via push (observed notifies observer) or pull (observer checks observed)?

Q9: What abstractions to you need to create to model the observer/observed? Will you need a new abstraction or can you build it into an existing one?

Q10: Before you do any coding for this task, look at the code you have currently and think about what methods/fields/classes you will need to change and what changes you will need to make. Note these methods and fields down briefly, and do this before you dive in and start coding.

Task 7 (delete if you are not doing Task 7)

Q11: What pattern/approach does InstaHam use here to alert the browser and how did you integrate it into your design?

Reflections

<your reflections here>
```

</details>


### State-Strategy-Observer or SSO (pun intended)

In the lab you'll be implementing a single sign on (SSO) system to allow you to login/signup users to an application through the use of many 'providers' such as Hoogle, and InstaHam.

To help you begin with implementing that let's discuss the basic mechanics behind SSO and how it works.  Furthermore, most of the code is already written for you so you'll just be modifying a small amount of code to see how you can apply state/strategy/observer patterns to a non-trivial example.

| :information_source:  NOTE: This problem has been massively trivialised and is more focused on the browser side changes in user state.  This is so that very little network domain knowledge is required to be able to solve the lab.  It invents its own protocol that is *roughly* based on OAuth2 (nowadays it's more common to use SAML due to numerous issues with OAuth, but SAML is significantly more complicated from a server side perspective). |
| --- |

### Task 0) Pre-reading

[Watch this video which gives an overview of the lab](https://www.youtube.com/watch?v=6v6qF6n07Xo) before you start.

### Task 1) Background: Authentication 🔑

> Authentication is confirming that the user is who they say they are, and authorisation is the act of giving users permission to a set of resources/actions.  We are merely concerned with authentication (i.e. 'login') in this lab.

**Q1: Why do we need authentication for applications such as gmail/myunsw/facebook? Write your answer in your blog post.**

##### SSO

Simply, SSO is a way to provide a universalised set of credentials across a set of applications.  That is you could use your google login for more than just gmail - you could use it to login to your favourite food blogger application or maybe a video sharing application.

<img src="imgs/state.png" />

> You can presume all access tokens are *always* valid, in reality you would have to validate the token with the third party.

To help you understand the problem here is an example login.

- User visits an application homepage
- They aren't authenticated so the application redirects them to login
- They choose the Hoogle provider and login using email + password
- The login was successful and so it redirects the request back to the application's login with the access token
- The application's application notices the user exists but not with the provider Hoogle so it registers it for this provider
- The application's application redirects the user to the home page, the user doesn't progress anywhere from here this is the end of our 'mock' simulation.

A few more details that aren't explicit in the above system;
- Providers may require different methods to login (username + password, email + password, two factor authentication, unique code sent via email, and so on...)
- The token will be the following object (for all providers) base64 encoded as a single token.

```javascript
{
    "email": "<email address of user>",
    "access_token": "<some generated token>",
    "provider": "<either 'LinkedOut', 'Hoogle' or 'InstaHam'>"
}
```

- Providers are linked to a common user via the email address

### Task 2) Understand the Starter Code & Implement Cache :file_cabinet:

To give you a better idea of how the system works, here is an example provided in one of the (already passing) tests in `SSOTest.java`.

```java
// Create a provider
Hoogle hoogle = new Hoogle();
hoogle.addUser("user@hoogle.com.au", "1234");

ClientApp app = new ClientApp("MyApp");
// Allow users to login using hoogle
app.registerProvider(hoogle);

// Create a browser instance
Browser browser = new Browser();

// Visit our client application
browser.visit(app);

// Since the browser has no initial login credentials
// it'll cause us to redirect to a page to select providers
assertEquals(browser.getCurrentPageName(), "Select a Provider");

// Since we are on the provider selection page we can 'interact' with the page
// and through that select a provider.  Interaction takes in a single `Object`
browser.interact(hoogle);

assertEquals(browser.getCurrentPageName(), "Hoogle Login");

// since we are on the provider form
// we can interact and provide a form submission
browser.interact(hoogle.generateFormSubmission("user@hoogle.com.au", "1234"));

// This should inform the browser that the form is filled
// Which will then authenticate the form with the third party provider
// which causes the browser to redirect back to the login page with token
// which causes the client application to validate the token
// resulting in a redirect back to the home page.
assertEquals(browser.getCurrentPageName(), "Home");
assertTrue(app.hasUserForProvider("user@hoogle.com.au", hoogle));
```

Looking at this example we can see the following;
- Each `page` acts as a state with transitions dependent on the interact function
- Browser only has very few public methods; `clearCache`, `interact`, and `visit`.

A series of Regression tests inside `SSOTest` already pass; when modifying the code you will need to ensure the tests stay passing.

Currently the browser doesn't remember old visits to an application, you'll notice that it only stores the "current" token for the user (look at `src/unsw/sso/Browser.java`), we want it so the browser remembers old visits!

**Task**: Implement caching so that the `Task2CacheTests` pass. 

The way you'll do this is left up to you but here are a few requirements;
- You do not have to handle any persistence here (so you can store the cache in the browser itself) and they don't have to be shared between browsers;
- You will need to cache multiple Token objects (look at `src/unsw/sso/Token.java`) as it currently only caches the 'current one';
- The `clearCache()` method should clear the cache completely for that instance;
- Caching is done on a `ClientApp` basis;

Once you have completed the task, in your blog post note down what you modified to implement this.

### Task 3) Open For Extension, Closed for Modification :globe_with_meridians:

### Part A

Currently the `ClientApp` only supports the `Hoogle` provider:

```java
public class ClientApp {
    private boolean hasHoogle = false;
    
    ...

    public void registerProvider(Object o) {
        if (o instanceof Hoogle) {
            hasHoogle = true;
        }    
    }

    ...

    public boolean hasHoogle() {
        return hasHoogle;
    }
}
```

**Q2: What code smells are present in the above code? How does this entail that the code does not adhere to the open-closed principle?**

**Task**: Refactor the provider logic in the `ClientApp` class so that it adheres to the open-closed principle. You will need functionality to register providers and check if a `ClientApp` has a certain type of provider, just like what is above. 

Currently the LinkedOut logic in the `ClientApp` is hardcoded to pass the tests, you will need to remove that hardcoding and make sure the logic works for it as well.

> Don't overthink this too much! If you want to be fancy and use generics go for it, but it can easily achieved with the basics. 

### Part B

Currently the `ClientApp` class stores a map of users:

```java
private Map<String, Boolean> usersExist = new HashMap<>();
```

**Q3: Explain why this logic doesn't adhere to the Open-Closed principle.**

**Task**: Determine what data structure would be the best design for storing users in the `ClientApp`, and refactor the user logic, including `registerUser` and `hasUserForProvider` to work around this revised design.

> Make sure that the `RegressionTests` and `Task2CacheTests` stay passing when you complete your refactoring!

Note down your refactoring steps for Parts A and B in your blog post.

### Task 4) State Pattern :page_facing_up:

Refactor the page system to use the State Pattern. 

**Q4: What are the different States present in this problem? What are the different actions/transitions that are common to each state? What occurs on each action, relative to each state?** This will form the basis for your use of the State pattern. You are welcome to make a State Transition Table if you like in your blog post.

Create a subpackage called `pages` inside `sso` and create a super-type called `Page.java`. 

**Q4: Will this be an interface or an abstract class? Why?**

**Task**: Using your design, implement the State Pattern to improve the page system.

> When implementing the State Pattern, one way to go about it can include having each action (method of the State interface/abstract class) return the next State. For no transition the method can return `this`.

Note down your refactoring steps in your blog post.

<details>
<summary>
Hint
</summary>

Since you are implementing a `back` button on the page system, pages will need to keep track of the previous page/state.

</details>

### Task 5) Strategy Pattern ⚽

Arguably the code present already implements the Strategy Pattern in a way, though the abstraction of logic is perhaps slightly different than what we might be used to.

**Q5: Identify the different 'strategies' present in this scenario.**

**Q6: Explain where and how the dynamic transitions between strategies in this context occur. How is this differently abstracted from other examples of the Strategy Pattern you have seen, for example the Restaurant system in the Week 5 Tutorial?**

### Task 6) Locking :lock:

Locking users if they attempt bad logins is important.  This task has you implement it so that if the user logs in incorrectly 3 times using the same provider; their account will become locked and will prevent login for that user to all applications where the provider is linked to their email.

Here is the updated state diagram that includes the locking state and transitions:

<img src="imgs/statev2.png" />

You will need to create a new page that represents this "lock" and if any *locked* user logs/attempts to login into *ANY* application (regardless of the provider) it should redirect them there.  This page should be called `Locked`.

Some more specifications/hints;
- You'll want a new state and will want to consider what new transitions have to exist for this state
- Providers are instance based in this case so you don't need to consider any sort of static/persisted locking here.
- Locked users can't be unlocked
- Pressing the back button on this state should send you back to select a provider *not* provider login.
- Consider the case where you are locked due to Provider A but not Provider B, you'll be successfully able to login to Provider B but you should still transition to the locked screen since your user is universally locked.
- Consider also the case where you have the following;
    - 1 application; W1, and 2 providers P1 and P2
        - Application W1 only has provider P1
        - You are locked from provider P2 due to trying to login onto some other application
    - You can login to W1 successfully with no issues if using provider P1
        - If you then register P2 with W1 and then you try to login using P2 it'll lock the user
        - Meaning you can't even use P1 to login anymore since locking is universal for all linked applications.
    - This case is quite complex so don't try to create a solution initially that handles this, solve the simple cases first then come back for the hard ones.

There are many ways to implement locking - we are going to use the Observer Pattern. The next three questions involve you designing your solution and implementation of the Observer Pattern.

**Q7: What is the observing entity/entities in this case? What entity/entities are being observed?**

**Q8: How will you implement notification, via push (observed notifies observer) or pull (observer checks observed)?**

**Q9: What abstractions do you need to create to model the observer/observed? Will you need a new abstraction or can you build it into an existing one?**

**Q10: Before you do any coding for this task, look at the code you have currently and think about what methods/fields/classes you will need to change and what changes you will need to make**. Note these methods and fields down briefly, and do this before you dive in and start coding.

**Task**: Implement locking using the Observer Pattern.

### Task 7) InstaHam (Choice) :pig:

You do not need to complete this task for full marks in this exercise.

InstaHam acts as a sort of magic link authentication, it works by linking to a specific instance of a browser for a specific user and then whenever the user tries to login through that browser it'll broadcast the token to the browser allowing it to login.  This isn't instant and takes around 500ms to send (it does so through a different thread).

The easiest way to explain this is through one of the tests;

```java
// create app/browser as usual
ClientApp app = new ClientApp("MyApp");
Browser browser = new Browser();

// create an instaham provider and bind it to our browser
InstaHam instaham = new InstaHam();
instaham.addUser("user@ham.com.au", browser);

// register ham but not hoogle
app.registerProvider(instaham);

browser.visit(app);
assertEquals(browser.getCurrentPageName(), "Select a Provider");

// we can select the ham provider
browser.interact(instaham);
assertEquals(browser.getCurrentPageName(), "InstaHam Login");

// and then we can select the user, this will trigger an auto sign-in around 500ms (ish) later
browser.interact("user@ham.com.au");

// we sleep for a bit more just to make sure since it's not accurate
// (probably too paranoid waiting 800ms though)
Thread.sleep(800);

// tada!
assertEquals(browser.getCurrentPageName(), "Home");
assertTrue(app.hasUserForProvider("user@ham.com.au", instaham));
```

The entire InstaHam provider is written for you in `src/unsw/sso/providers/InstaHam.java` and if you look inside that class you'll see the following function;

```java
public void broadcastCode(String email) {
    if (users.containsKey(email)) {
        Thread thread = new Thread(() -> {
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

            String code = UUID.randomUUID().toString();
            userCodes.get(email).add(code);
            users.get(email).interact(getToken(email, code));
        });
        thread.start();
    }
}
```

This will let you 'broadcast' a code/login to all browsers, you'll notice that it automatically interacts with the browser at the very end.  You don't need to understand how threading works or anything related to that here, just call this function when you want the code to be sent out and the browser to auto-login.

Some hints
- You'll need to make some small changes to the `InstaHam` provider to connect it to your code so think about how you can do that

**Q11: What pattern/approach does `InstaHam` use here to alert the browser and how did you integrate it into your design?**

| :information_source:  Hint: This may seem scary, but don't panic!  Don't focus on things in the class that you don't understand; focus on just treating it as a black box initially, as you read and play around with the tests the class will become more obvious and hopefully will become easier to understand! |
| --- |

## Week 05 - Core Blog - Reflect on the SSO Lab

Well done on making it this far through the lab - whether you completed all the core tasks or not! 

Take some time to reflect on what you learned by completing this lab, what was the most challenging aspect of the lab and if you were to do it again, what you would have done differently.

<img src="imgs/quote.png" />
