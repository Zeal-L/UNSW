## Lab09 - Exercise - Deploy (2 points)

In this lab exercise, you will write a very simple app, make sure it is type safe and then deploy to Microsoft Azure.

This may help you for the deployment aspect of your project in Iteration 3.

### Part 1 - Functionality

Complete the function definitions in `number_fun.py`. You will need use the `typing` module to put type checking on all of your function definitions- parameters and return values. Some tests to sanity check your code are in `numbers_test.py`, however these will not test whether your typing is correct.

### Part 2 - Flask Server and HTTP Tests

Write a flask server in `server.py` which has endpoints that call each of the functions in `numbers_fun.py`. All endpoints will be `GET` requests and you can choose the output format.

Write a few HTTP tests in `numbers_http_test.py`. Use a global variable to store the URL which you will later replace with the URL of your deployed server on the internet.

### Part 3 - Deployment

Deploy your app using alwaysdata (in accordance with instructions from lectures) so that it can be accessed online from anywhere. You will need to research how to do this, create accounts, etc.

Once this is done, copy and paste the URL into the variable inside `numbers_http_test.py` and make sure that all your tests pass.

Well done, you've deployed your first ever app to the internet!

### Part 4 - CI/CD Setup (Not required)

If you want to extend yourself, set up continuous integration so that whenever you push in your repository, a pipeline is run which runs `pylint`, `pytest` and `coverage` is run, and if the pipeline fails the repository fails to redeploy. This can be a challenging activity.

Hint: Have a look at the `.gitlab-ci.yml` files in repositories for other lab exercises - they should give you an idea of how to setup CI in GitLab.
