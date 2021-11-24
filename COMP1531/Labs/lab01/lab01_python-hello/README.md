## Lab01 - Exercise - Hello (1 point)

To proceed to the second part of this lab, you must have access to Python version 3.7 or later. It is available on the CSE computers via the `python3` command, which is what these instructions assume you will be using, but you're encouraged to set up Python on your personal computer as well.

## Setting up python on your own computer

While it's your responsibility to determine the best way to install software on your own devices, we provide the following information to give some guidance.

For **Mac** users:
 * Mac OSX comes with a version of Python already installed, but it is v2.7 so is **NOT** suitable for this course.
 * [This guide](https://docs.python-guide.org/starting/install3/osx/) describes how to install Python 3 via Homebrew and is a popular means of doing so.
 * Alternatively, you can get it from the [Python website](https://www.python.org/downloads/release/python-374/).

For **Windows** users:
  * There are various means to get a UNIX like environment on Windows ([CSE Ubuntu](http://mirror.cse.unsw.edu.au/pub/cseubuntu-vm/) in a VM, Cygwin, WSL, etc.). It's usually not hard to install Python 3.7 into one of them.
  * The official release is available from the [Python website](https://www.python.org/downloads/release/python-374/), if you don't know how to install software in your existing set up.

For **Linux** users:
  * On newer Debian and Ubuntu-based systems Python 3.7 can be obtained via `sudo apt-get install python3.7`.
  * If you're using something else, we assume you already know how to install the right version of Python.

## Setting up python for COMP1531

In this course you will be using a variety of tools and libraries that do not come bundled with python and have to be installed separately. To install everything you need in your CSE account:

```
$ pip3 install $(curl https://www.cse.unsw.edu.au/~cs1531/21T1/requirements.txt)
```

The final step is to add the extra tools to your `PATH`. You can do this with:

```
$ export PATH=$HOME/.local/bin:$PATH
```

To ensure this is done every time you log in or open a new terminal window:

```
$ echo -e '\nexport PATH=$HOME/.local/bin:$PATH' >> ~/.profile
$ echo -e '\nexport PATH=$HOME/.local/bin:$PATH' >> ~/.bashrc
```

To install these things on your own computer you should be able run the same commands (if you're using linux) or potentially slightly modified commands on Windows or Mac, depending on how you installed python.

## Hello Python

You have been introduced to python in week 1 so we will just get familiar with creating and running simple python programs. Python is an interpreted language so does not require compilation like C does. That means executing python programs is as simple as one command.

**Instructions:**

1. Open the `hello.py` file.
2. Complete the file so it prints "Hello World"
3. Run it from the command line

    ```bash
    python3 hello.py
    ```

4. Commit your changes
