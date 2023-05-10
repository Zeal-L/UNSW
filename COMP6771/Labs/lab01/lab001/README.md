# 001: Development Environment

Modern C++ development environments are as varied and potentially complicated as the language itself.
In this course, we have made an effort to _remove_ as much of the complexity around the toolchain as possible so that we can focus on the real goal: learning C++.

The purpose of this lab is to introduce and fully set up the minimum necessary toolset we will use in this course.
We shall be using:
- CSE Gitlab as the platform to distribute code.
  - Basic Git will also be required
- GCC 10.2+ or Clang 11.0.1+ as our C++20 compiler.
  - These are the versions installed on the CSE machines and easily acquired on UNIX-like systems.
  - Note: Clang on MacOS has a different versioning system than on Linux-based systems. You need at least XCode version 13 or greater (Apple Clang v13+).
- CMake as our build system.
  - CMake relies on `ninja`, a smaller and faster program similar to `make`.
- Either VS Code or CLion as the editor
  - You are free to use any editor you like but we cannot provide assistance except for the above two.

## 1. Gitlab & Git Set-Up

What you're looking at is your own repository (repo) on Gitlab for this lab task.

If you're familiar with GitHub then you should find GitLab very similar. What you're reading right now is the `README.md` file stored in the repo.

Feel free to browse GitLab in order to familiarise yourself with it. If you're not familiar with git, the following sections should help get you started with learning it.

If you have used Gitlab before in other courses, the below steps are not necessary. If however this is your first time using Gitlab, you **must** ensure you do the following.

### Adding your SSH Key to GitLab

The following steps **must** be performed by running the commands on where you wish to work: either the CSE systems, or your own computer. If you wish to work from more than one computer, you must **also** do the same for each different machine.

1. You need to add your CSE ssh key to your `gitlab.cse.unsw.edu.au` account. Here is how you do that:
First print your SSH key. If you have one, this command should work.

    ```
    $ cat ~/.ssh/id_ed25519.pub
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPs4UgqpRj4RLeOtbldYPDqsT8H/40BlVAZq+nV7fTFN z5555555@williams
   ```

2. If you couldn't print an SSH key with the above command, you need to generate a new SSH key. You can do it like this (just hit return for each question).

    ```
    $ ssh-keygen -t ed25519
   Generating public/private ed25519 key pair.
   Enter file in which to save the key (~/.ssh/id_ed25519):
   Enter passphrase (empty for no passphrase):
   Enter same passphrase again:
   Your identification has been saved in ~/.ssh/id_ed25519
   Your public key has been saved in ~/.ssh/id_ed25519.pub
   The key fingerprint is:
   ...
   The key's randomart image is:
    ...
    ```

3. To add your key to GitLab, go to your [account's SSH Keys](https://gitlab.cse.unsw.edu.au/-/profile/keys) page.
4. If you're asked to log in again, do so.
5. Cut-and-paste your ssh-key (the entire line printed by cat ~/.ssh/id_ed25519.pub) into the "Key" field. Don't cut-and paste z5555555's ssh key above - cut-and-paste your ssh-key! The title field should be filled in automatically.
6. Click the green **Add Key** button

**Remember**: SSH keys are per account per computer. If you frequently change computers and/or user accounts on those computers, you will have to repeat this process each time.


### Getting `git`

Git is a distributed version control system. It allows you to record changes to a set of files over time and synchronise those changes across many *repositories*. What you're looking at now is one of these repositories, stored on a server at UNSW. You don't have direct access to that computer, so in order to make changes to files contained within it, you need to copy it to a *local* repository. You can make changes to this local repository then "push" those changes to GitLab. To do that, however, git needs to be installed and configured:

1. If git is installed on the computer you are using. You can do this by running:
    ```bash
    $ git status
    ```
    If it is installed you will see something like
    ```
    fatal: Not a git repository (or any of the parent directories):
    ```
    If you do not have git installed, you will see something like
    ```
    bash: git: command not recognized
    ```
    If this is the case, you will have to set it up using the following instructions
    - **Linux** - Follow instructions at https://git-scm.com/download/linux
    - **Mac** - Either download from https://git-scm.com/download/mac or install via Homebrew or similar.
    - **Windows** - Download from https://gitforwindows.org/

    There are other means of getting git for all of these platforms. You are free to use whatever means works best for you.

2. Configure git if you have not used it before. The following commands will do that.
    ```bash
    $ git config --global user.name "Your Name"
    $ git config --global user.email "email@example.com"
    $ git config --global push.default simple
    $ git config --global pull.rebase true
    ```

### Basic `git` Usage

It is assumed knowledge that you have worked with `git` before, so this next section about `git`'s fundamental commands will be brief. If you still feel like you do not know `git` confidently enough, ask your tutor for help.

**Important**: below is an explanation of common Git commands and is _optional_ reading for this lab.

#### Cloning a Repository

A `git` repository stored on a server somewhere is called the _remote_. Through the process of _cloning_, you can download a copy of the remote repository to your **local** machine. This repository is the called the _local_.

To achieve this, you must copy the SSH URL of the remote repository and use it like so:
```sh
# git clone <remote_url> <local_folder_name>

git clone gitlab@gitlab.cse.unsw.EDU.AU:COMP6771/23T1/students/z5555555/lab001.git
```

From here, you are able to start work.

#### Making Commits

When you have started working and made some reasonable progress, you should take a snapshot of the current repository in case you ever need to go back to an earlier version.

There are three commands you will use very frequently:

- `git status` to show the state of the repository
- `git add` to add files to the next commit
- `git commit`, to actually make a commit

`git status` will tell you what files have been created since the last commit, which files have been modified since the last commit, and which files will be included in the next commit.

`git add` will add files or directories to the next commit. Use it like so:
```sh
# git add file_or_directory1 [file_or_directory2, ...]

git add foo foo_dir
```

Once you have files added to the commit, you need to commit the changes.
This is done with the `git commit` command:
```sh
# git commit -m "an insightful commit message

git commit -m "completed lab001!"
```

It is recommended to commit frequently so that if you ever need to go back to an earlier version of the code you can do so in a fine-grained manner.

#### Syncing Your Changes with the Remote

Committing only makes changes to the local, but for purposes of submission, you will need to sync your changes with the remote repo on GitLab.

Also, sometimes there are updates to repos, and you'll want to fetch these too.

Getting updates from the remote can be done via `git pull`.
Putting update onto the remote can be done via `git push`.

Everytime you start working on some code, remember to pull:
```sh
git pull
```

And everytime you have made a commit (or two, or more...), remember to push:
```sh
git push
```

That's all there is to it.

#### Other `git` Commands

Advanced users of `git` will know that `git` is far more powerful than the brief instructions described here.

Other topics of interest:
- branching
- merging
- rebasing
- squashing commits

You will likely not encounter a need for these features (except potentially merging) during this course, but you are welcome to research them yourself.

## 2. C++20 Compiler

Since we will be learning C++20 in this course, we naturally will need a C++20 compiler.
We only officially support GCC-compatible compilers, i.e. GCC and Clang.
You do not have to exactly the version of the compiler on CSE -- C++ and compiler vendors greatly value backwards-compatibility with older code. However, you must ensure at least that your code compiles and runs on the CSE machines for the purposes of submission.

### Using the CSE Machines

All of the supported compilers and their associated build toolchains are already installed on the CSE computers. You can access them in-person or through [VLab](https://taggi.cse.unsw.edu.au/Vlab/).

You **should NOT** use an SSH connection to access the CSE Machines. The SSH connection **does not** support the debugging feature of editors like VS Code, and you will severly hinder your productivity if you decide to work without a debugger.

### Using Linux

We only officially support Ubuntu 20.04 or later Linux distributions.
If you are using Linux, it is assumed you have familiarity using a package manager.

You can install `g++` via
```shell
$ sudo apt update && sudo apt install g++-X
```
where `X` is `10` or higher. You should install at least `g++-10`.

If you'd like to use `clang`, you'll need to add the LLVM apt repository to the list of system repositories:
```shell
# From https://apt.llvm.org/

# Most recent version (backwards compatible)
bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"

# To install a specific version of LLVM:
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh <version number>
```
The above script from the LLVM project will install `clang` automatically.
If `clang++` is still not available, then you can run:
```shell
$ sudo apt update && sudo apt install clang++-X
```
where `X` is `11` or higher.

### Using Windows

We only officially support Windows through [Windows Subsystem for Linux (WSL2)](https://learn.microsoft.com/en-us/windows/wsl/install).

You should follow the above linked instructions and install Ubuntu 20.04 or later.

From here, follow the same steps as in the Linux section.

### Using MacOS

If you would like to use MacOS, it is much more convenient to use the default C/C++ compiler that ships with XCode's native development tools. This compiler is Apple's own special version of Clang/LLVM.

You can download the most recent version of XCode from [the app store](https://apps.apple.com/au/app/xcode/id497799835?mt=12). Once it downloads, you must open it at least once and accept the license agreement.

Alternatively, you can download the Developer Command Line Tools from a terminal with the command
```shell
$ xcode-select --install
```

You should ensure that at least XCode version 13 is installed. If you have an earlier version, you likely will not be able to compile all code used in this course.

This has been tested on at least MacOS Ventura 13.1.

## 3. CMake

CMake is a cross-platform meta-buildsystem (i.e., it generates platform specific build systems from CMake script files) and is available at [the CMake website](https://cmake.org/download/).

Once you download it, you must ensure the `cmake` command is available to be used on the commandline.
You can make sure of this by opening a new terminal and running
```shell
$ cmake --version
```
If you don't see at least version 3 of CMake be printed from the above command, you likely will need to add the CMake binary to your PATH variable. The details of how to do this vary depending on which operating system you are using:
- [Ubuntu Linux (and WSL2 Ubuntu)](https://help.ubuntu.com/community/EnvironmentVariables)
- [MacOS](https://support.apple.com/en-gb/guide/terminal/apd382cc5fa-4f58-4449-b20a-41c53c006f8f/mac)

You will also need to download [ninja](https://github.com/ninja-build/ninja/wiki/Pre-built-Ninja-packages), a small and fast (like a ninja) build tool meant to replace `make`. Likewise to CMake, you must ensure `ninja` is also available to be used on the commandline.

Whilst this course uses CMake, you will not need to know CMake in any depth. Almost all of the buildsystems used in this course are written in a simple fashion and are commented so if you spend some time reading the documentation it should be easy to understand.

Nevertheless, some of the more common commands will be introduced below. A more complete tutorial about CMake can be found [here](https://cmake.org/cmake/help/latest/guide/tutorial/index.html)

**Important**: below is an explanation of common CMake commands and is _optional_ reading for this lab.

### Basic CMake Usage (CMakeLists.txt)

CMake fundamentally works on "targets". A target may be an executable, a static library, or something more exotic. We will only be using executable and static libraries in this course.

A typical CMake workflow follows the configure -> generate -> build cycle.

When CMake is first run on a `CMakeLists.txt` file, it will configure itself based on what is written in that file. This can include:
- defining targets
- setting build flags for different build modes (e.g., flags for a `Debug` build, flags for an optimised `Release` build, etc.)
- setting up test executables.

After configuration, CMake generates a delegate buildsystem (using e.g. `make`, `ninja`, etc.), which then can be built separately from CMake.

Any time the CMakeLists.txt is modified, the buildsystem must be regenerated.

#### Adding new executables

To add a new exectuble target, use the `add_executable` command:
```cmake
add_executable(NAME SOURCE_FILE [MORE_SOURCE_FILES])
```

#### Adding new static libraries

To add a new static library, use the `add_library` command:
```cmake
add_library(NAME SOURCE_FILE [MORE_SOURCE_FILES])
```

#### Linking libraries into executables

Software libraries are only useful when used with an executable.
To link a library with an executable in CMake, you can use the `link_libraries` command:
```cmake
link_libraries(LIBRARY_TARGET_NAME)
```
This has the effect of making any _new_ executable targets defined after this command be automatically linked with `LIBRARY_TARGET_NAME`.

An alternate version of this command that affects only a single, pre-existing target is the `target_link_libraries` command:
```cmake
target_link_libraries(executable_target PUBLIC lib1 [lib2 ...])
```
For brevity's sake we only have used the `link_libraries` command, but modern CMake heavily prefers the `target_`-prefixed version of CMake commands.

#### Adding compiler flags

To add compiler options to _all_ subsequent targets (executables and libraries), you can use the `add_compile_options` command:
```cmake
add_compile_options(opt1 [opt2 ...])
```
There is also a `target_compile_options` command, which affects only a single, predeclared target:
```cmake
target_compile_options(target PUBLIC opt1 [opt2 ...])
```
Note that the options given to these commands are passed verbatim to the underlying compiler.
For GCC and Clang this is not an issue since they are virtually 100% commandline-compatible.

### Running CMake from the commandline

Once a CMakeLists.txt is written, various invocations of the `cmake` command can be used to generate and build your code.

Most modern IDEs provide GUI controls to do this, but it can also be done on the commandline.

First, `cmake` needs to configure and generate the build system:
```shell
cmake
  -S path_to_root_folder # this is the "source" directory -- where the CMakeLists.txt file lives!
  -B path_to_build_folder # this is where CMake will put its generated buildsystem and built binaries
  -DCMAKE_BUILD_TYPE=<Debug|Release> # build in Debug mode? or build a Release version?
```
It is best to keep the source directories and build directories separate.
These so-called "out-of-source" builds can live inside a project's root folder in a subdirectory, however.
For example, if a project lives in the folder `foo`, you can specify the build directory to be `foo/build`.

Once CMake is configured, we can easily build:
```shell
cmake --build path_to_build_folder [-t optional_target_name]
```
If no explicit target is given, CMake will default to building everything.

By default, CMake places its executables in the build folder that was specified during configuration.
Once a target is built, it is executable like any other program!

## 4. Editor

Whilst you are free to use your own editor of choice, we officially support the two most-used ones: CLion and VS Code.

### CLion

Jetbrains' suite of IDEs follow a yearly subscription model, but [students of UNSW can sign-up for an educational license](https://www.jetbrains.com/shop/eform/students) and use their products for free until graduation.

CLion is the flagship C/C++ editor offered by Jetbrains. It offers first-class CMake support and is usable from installation with very little customisation necessary.

You can learn how CLion integrates with CMake [here](https://www.jetbrains.com/help/clion/quick-cmake-tutorial.html).

Available on Linux, Windows, and MacOS.

### VS Code

Microsoft's [Visual Studio Code (VS Code)](https://code.visualstudio.com/Download) is a lighter-weight version of their popular Windows-only Visual Studio editor.

VS Code is extremely flexible in what languages it can be used with. This flexibility is achieved via an extension (i.e., plug-ins) system.
After downloading VS Code, you will need to install at least these extensions to make a complete and cosy C++ development environment:
- [Better C++ Syntax](https://marketplace.visualstudio.com/items?itemName=jeff-hykin.better-cpp-syntax)
- [C/C++ (from Microsoft)](https://marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools)
- [C/C++ Extension Pack](https://marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools-extension-pack)
- [CMake](https://marketplace.visualstudio.com/items?itemName=twxs.cmake)
- [CMake Tools](https://marketplace.visualstudio.com/items?itemName=ms-vscode.cmake-tools)
- [Clangd](https://marketplace.visualstudio.com/items?itemName=llvm-vs-code-extensions.vscode-clangd)

You can learn how VS Code integrates with CMake [here](https://code.visualstudio.com/docs/cpp/cmake-linux#_select-a-kit)

Available on Linux, Windows, and MacOS.

### !! Important !!

One word of caution is: do **NOT** use a basic text editor like gedit. Basic text editors do not provide intellisense or static analysis tools (such as providing red underlines when code syntax is miswritten), and it is extremely likely you will unintentionally waste time looking for code errors when a more advanced IDE like CLion or VS Code would have done this work for you.

## 5. Putting it Altogether

Once all the requisite software is installed, it is time to your new environment to the test.

In `src/main.cpp`, there is a small program that outputs a secret message to standard output. Note: you should not modify this program.

Your job is to successfully build and run this program and to save the output of this program to `src/answers.txt`. 

Then, you should push `src/answers.txt` to the main branch (called either `main` or `master`) of this project's repository on Gitlab.
