# Lab 01

### Due: Week 2 Monday, 8am

### Value: 8 marks towards the Class Mark

## Aims

* Become familiar with course practices for labs
* Revise how to use GitLab effectively
* Gain familiarity with Java development using the VSCode IDE
* Learn the basic syntax of the Java Programming Language
* Implement a simple class
* Become familiar with the blogging process and set goals for the course 

## Getting Setup

* **[Git Refresher](spec/git.md)** If you need a refresher on Git, complete this exercise. We will be using git for all lab, assignment and project work throughout the course - so make sure you're comfortable using it. If you're confident with git you can skip this exercise. 
* **[Java Setup](spec/java_setup.md)** - Follow these instructions to setup your local development environment for Java. 
    * We use VSCode in this course. 
    * You are welcome to use any IDE you like, but we will only be able to provide support for you in classes, help sessions on the forum for VSCode - so you will need to and research solutions to problems yourself if you want to use a different IDE
    * Don't use a text editor as we will be dealing with large projects with many files. Over the course we will explore how to use VSCode to make coding life easier.

## Overview

The overall class mark for each week is out of 8 marks. 2 marks come from tutorial participation and 6 marks come from completing the following exercises.

## Core Exercises

* [Average](spec/average.md) (1 mark)
* [Splitter](spec/splitter.md) (1 mark)
* [Satellite](spec/satellite.md) (2 marks)

## Core Blogging

* [My First Blog Post](spec/first_blog.md)
* [Goal Setting & Looking Ahead](spec/goals.md) (2 marks)

## Choice Exercises

The following exercises are optional but are good if you want to practice Java Programming and design thinking to warm up for the course!

* [Pineapple on Piazza](spec/piazza.md)
* [Scrabble Subwords](spec/scrabble.md)
* [Physical Design](spec/design.md)

## Submission

**Make sure you have committed all of your changes before submitting**.

To submit, make a tag to show that your code at the current commit is ready for your submission using the command:

```bash
$ git tag -fa submission -m "Submission for Lab 01"
$ git push -f origin submission
```

Or, you can create one via the GitLab website by going to `Repository > Tags > New Tag`. 

We will take the last commit on your `master` branch before the deadline for your submission.

## Marking

When marking your design and programming lab exercises, the following aspects are considered:

* Exercise is submitted on time;
* Code passes pipeline with provided JUnit tests / your tests;
* Code solves the problem and is not a hardcoded solution;
* Code is written cleanly and with good style;
* Solution is well designed, using the design principles and patterns intended by the activity; and
* Any other requirements outlined in the problem specification.

When marking your written blog posts, the following aspects are considered:

* Answers are comprehensive and thoughtful;
* Answers address all aspects of the question; and
* Answers are in the correct format as specified by the question.

Many lab exercises in future weeks will consist of a practical design and programming exercise and a written blog post reflecting on the activity. During marking you should bring up your code and your blog post and talk through your solution, thought process and reflections using your blog post as a prompt.
