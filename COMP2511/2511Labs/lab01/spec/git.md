## Git and GitLab - Crash Course

If you've taken COMP1531 recently and/or are relatively fluent in git, then feel free to move on and skip this.

If you're familiar with GitHub then you should find GitLab very similar. You'll observe that there is a copy of these instructions in the repository (`README.md`) as well as a few files and folders relating to this lab exercise.

Feel free to browse GitLab in order to familiarise yourself with it. If you're not familiar with git, the following sections should help get you started learning it.

#### Adding Your SSH Key to GitLab

The following steps should be performed by running the commands on the CSE system. You may also wish to do the same on your personal computer to avoid repeatedly entering your username and password.

1. You need to add your CSE ssh key to your gitlab.cse.unsw.edu.au account. Here is how you do that:
First print your CSE ssh key. If you have one, this command should should work.

    ```
    $ cat ~/.ssh/id_rsa.pub
    ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAyNSzIDylSPAAGLzUXdw359UhO+tlN6wWprSBc9gu6t3IQ1rvHhPoD6wcRXnonY6ytb00GpS4XRFuhCghx2JNVkXFykJYt3XNr1xkPItMmXr/DRIYrtxTs5sn9el3hHZIgELY8jJZpgIo303kgnF0MsB7XpqCzg7Iv6JGkv7aEoYC/MNr07hXE8iQjYIHDMdO9HxGI80GyMqb1hF+RSpQTNvXQvH56juu9VXt5OwJjOqSVa4SfsEICqdn+3k9w8Z4EaD93Eeog3hz0RoTrme8h/sJenXydJ0w9ZOs0By4fjqKFYPsYEs1K6SHma+kPByZM9COgKHZwOZHH1m24HOITQ== z5555555@williams
   ```

2. If you couldn't print an ssh key with the above command, you need to generate a new ssh key. You can do it like this (just hit return for each question).

    ```
    $ ssh-keygen
    Generating public/private rsa key pair.
    Enter file in which to save the key (/import/kamen/3/z5555555/.ssh/id_rsa):
    Created directory '/import/kamen/3/z5555555/.ssh'.
    Enter passphrase (empty for no passphrase):
    Enter same passphrase again:
    Your identification has been saved in /import/kamen/3/z5555555/.ssh/id_rsa.
    Your public key has been saved in /import/kamen/3/z5555555/.ssh/id_rsa.pub.
    The key fingerprint is:
    b8:02:31:8b:bf:f5:56:fa:b0:1c:36:89:ad:e1:cb:ad z5555555@williams
    The key's randomart image is:
    ...
    ```

3. To add your key to GitLab go to https://gitlab.cse.unsw.edu.au/-/profile/keys
4. If you're asked to log in again, do so.
5. Cut-and-paste your ssh-key (the entire 200+ character line printed by cat ~/.ssh/id_rsa.pub) into the "Key" field. Don't cut-and paste z5555555's ssh key above - cut-and-paste your ssh-key! The title field should be filled in automatically.
6.  Click the green **Add Key** button

#### Using git

This exercise is intended to help you (re)familiarise yourself with git. As git usage was covered in COMP1531, a prerequisite for this course for the past 3 years, we expect most students to already be familiar with it, so this exercise should not take you long. If you're taking this course under the old program (i.e. you've not taken COMP1531) and you've not become familiar with git via other means then this exercise may require more careful attention.

#### Getting git

Git is a distributed version control system. It allows you to record changes to a set of files over time and synchronise those changes across many *repositories*. You've already seen one git repository earlier in the lab: the one stored at `gitlab.cse.unsw.edu.au`. You don't have direct access to that computer, so in order to make changes to files contained within it, you need to copy it to a *local* repository. You can make changes to this local repository then "push" those changes to GitLab. To do that however, git needs to be installed and configured:

1. git is installed on the computer you are using. You can do this by running:
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
    - **Mac** - `brew install git`

2. Configure git if you have not used it before. The following commands will do that.
    ```bash
    $ git config --global user.name "Your Name"
    $ git config --global user.email "email@example.com"
    ```

#### Cloning

Cloning a *repository* (a repository or repo is just a directory that is linked with git) copies to your computer all the files in the repo as well as a complete history of what changes, or *commits*, created those files. Cloning a repo is necessary before you can start making your own changes.

For each lab and assignment in this course, a repo will be created for you on *GitLab*. You will use it to store your work as you complete it. To clone this week's repo run:

```
$ git clone gitlab@gitlab.cse.unsw.EDU.AU:z5555555/20T3-cs2511-lab01.git
```

#### Making a commit

Now that you have cloned the repo, you are ready to work on the codebase locally.

A commit represents a set of changes to the files in a repository as well as a message describing those changes for human readers. A good use of git involves a lot of commits with detailed messages.

Before you can commit, you have to *stage* your changes, effectively telling git what changes you actually want to commit and what changes you don't.

Making commits doesn't actually replicate your changes to the remote repository on GitLab. For that you need to *push* your commits, uploading them to the remote server. When collaborating with others, it is important not only to commit frequently, but also to push often.

In general, the commands to commit and push are as follows:
```bash
$ git add [files_to_commit] # Stage
$ git commit -m"Detailed message describing the changes" # Commit
$ git push # Push
```

Follow these steps to see them in action:

1. Add a new file called `HelloWorld.java` in the repo directory
2. Add the following lines of code to the file using your favourite text editor and save.

    ```java
    class HelloWorld {
        public static void main(String[] args) {
            System.out.println("Hello, Welcome to COMP2511!");
        }
    }
    ```
3. Go back to your terminal and enter the following commands:
    ```bash
    git add HelloWorld.java
    git commit -m "Created first java program HelloWorld.java"
    git push
    ```
4. **MAKE SURE YOU UNDERSTAND THE PURPOSE OF EACH OF THE 3 ABOVE COMMANDS!** If you are unsure about any of them, ask your tutor or lab assistant.
5. Go back to GitLab and confirm that your changes have been pushed to the server.

#### Working with others
Usually when you are using git, it is in a team. That means that you will not be the only one who is making the changes. If someone else makes a change and pushes it to the server, your local repo will not have the most up to date version of the files. Luckily, git makes it easy to update our local copy with the `git pull` command.

This command checks the remote server that your local repo is linked to and makes sure that all of your files are up to date. This ensures that you don't accidentally do things like implement the same thing someone else has already done and also lets you use other people's work (e.g. new functions) when developing.

Pulling regularly is one of the **most important** practices in git!

Unfortunately, at the moment you are just working individually. But GitLab still gives us a nice way to practice a `git pull`.

**Summary:**
1. View your repo on GitLab.
2. Click on the HelloWorld.java file
3. Click 'Edit' on the right-hand side.
4. Add a Java comment to the top of the file as shown below and click the ‘Commit Changes’ button at the bottom of the screen

    ```java
    // A simple Java Program
    ```

5. This will have changed the `HelloWorld.java` file on the server but not on your local environment. To fetch these changes use the git pull command from your terminal
6. Confirm that your version of HelloWorld.java now has the changes you made on the web page


#### Branching
**Branches** are a vital part of git and are used so people can work on separate parts of the codebase and not interfere with one another or risk breaking a product that is visible to the client. Breaking something on one branch does not have an impact on any other.

Good use of git will involve separating parts of the project that can be worked on separately and having them in their own feature branch. These branches can then be merged when they are ready.

Useful commands for branches:

```bash
$ git checkout -b [new_branch_name] # Create a new branch and switch to it
$ git branch                        # List all current branches
$ git checkout [branch_name]        # Switch to an existing branch
```

Follow these instructions to create a branch:
1. Make your new branch with: `git checkout -b first_new_branch`
2. List your branches to see that you have indeed swapped (use the above commands)
3. Open the `HelloWorld.java` file and change the comment at the top of the file to Javadoc style comment as shown below:

    ```java
    /**
    * A simple java program that prints a hello world message to the console
    *
    */
    ```

4. Try to push your changes to the server using the commands you learnt in the *Making a commit* section
5. The above step should have given you the following error:

    ```
    fatal: The current branch first_new_branch has no upstream branch.
    ```

    This means that the branch you tried to make a change on doesn’t exist on the server yet which makes sense because we only created it on our local machine.
6. To fix this, we need to add a copy of our branch on the server and link them up so git knows that this new branch maps to a corresponding branch on the server

    ```
    git push -u origin first_new_branch
    ```

**Note:** The final step only needs to be done for the first time you try to push using a new branch. After you have run this once, you should go back to simply using git push

#### Merging
Merging branches is used to combine the work done on two different branches and is where git's magic really comes in. Git will compare the changes done on both branches and decide (based on what changes were done to what sections of the file and when) what to keep. Merges are most often done when a feature branch is complete and ready to be integrated with the master branch.

Since we have finished all that we are going to do (and think there are no bugs) on our *first_new_branch* we can merge it back into master.

**NOTE**: It is strongly recommended, both in this course and in general, to always ensure the code on the `master` branch compiles and is free of bugs. The latter is naturally harder to achieve than the former, but you should endeavour to keep master as *stable* as possible.

Another recommendation is to merge master into your branch before merging your branch into master as this will ensure that any merge into master will go smoothly.

In general, merges are done by:

```bash
git merge [target] # Merge the target branch into current
```

**Note:** A successful merge automatically uses the commits from the source branch. This means that the commits have already been made, you just need to push these to the server (`git push`)

To merge your changes from above:
1. Switch back to the `master` branch using one of the commands from the above section
2. Merge in the changes you made in the other branch

    `git merge first_new_branch`

3. Push the successful merge to the server to update the master branch on the server

#### Merge conflicts
Merge conflicts are the one necessary downside to git. Luckily, they can be avoided most of the time through good use of techniques like branches and regular commits, pushes and pulls. They happen when git cannot work out which particular change to a file you really want.

For this step we will engineer one so you can get a taste of what they are, how they occur and how to fix them. This will be the LAST time you will want one. The process may seem involved but it is quite common when multiple people are working at a time.

Follow these steps:

1. Change line 3 of `HelloWorld.java` to

    ```java
    System.out.println("Hello, Welcome to Java!");
    ```

2. Add, commit and push your changes
3. Switch to your *first_new_branch*
4. Change line 3 of `HelloWorld.java`

    ```java
    System.out.println("Hello, Welcome to merge conflicts!");
    ```

5. Add, commit and push your changes
6. Merge master into your current branch
7. This sequence of steps should make a merge conflict at the third line of `HelloWorld.java`

#### Resolving a merge conflict
Resolving a merge conflict is as simple as editing the file normally, choosing what you want to have in the places git wasn't sure.

A merge conflict is physically shown in the file in which it occurs.
`<<<<<<<` marks the beginning of the conflicting changes made on the **current** (merged into) branch.
`=======` marks the beginning of the conflicting changes made on the **target** (merged) branch.
`>>>>>>>` marks the end of the conflict zone.

E.g.

```
This line could be merged automatically.
There was no change here either
<<<<<<< current:sample.txt
Merges are too hard. This change was on the 'merged into' branch
=======
Merges are easy. This change was made on the 'merged' branch
>>>>>>> target:sample.txt
This is another line that could be merged automatically
```

This above example could be solved in many ways, one way would be to just use the changes made on the target branch and delete those made on the current branch. Once we have decided on this we just need to remove the syntax. The resolved file would be as follows

```
This line could be merged automatically.
There was no change here either
Merges are easy. This change was made on the 'merged' branch
This is another line that could be merged automatically
```

We would then just commit the resolved file and the merge conflict is finished!

To fix the conflict you created:
1. Open the `HelloWorld.java` file and decide which change you want to keep
2. Remove the merge conflict syntax
3. Add, commit and push the resolved merge conflict
