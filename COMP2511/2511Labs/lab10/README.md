# Lab 10

### Due: Week 10 Sunday, 5pm

### Value: 8 marks towards the Class Mark

This lab will be partially automarked, and partially manually marked.

## Aims

* Apply the Iterator Pattern to non-linear data structures
* Revise Graphs, Depth-First Search and Breadth-First Search
* Understand the concepts of Iterators and Iterables
* Apply the Visitor Pattern

## Overview

The overall class mark for each week is out of 8 marks. 2 marks come from tutorial participation and 6 marks come from completing the following exercises.

## Core Exercises & Blogging

In order to achieve full marks for the lab, you will need to complete the following core exercises:

* [A Visiting Calculator](spec/calculator.md) (2 marks) (only need to complete Part 1)
* [Graph Iterator](spec/graph.md) (2 marks)
* [Gratitude](spec/gratitude.md) (2 marks)

## Choice Exercises & Blogging

* [Narrative Design](spec/narrative.md)
* [The Flaw in the Plan](spec/flaw.md)

## Revision Exercises

We have put together a series of exercises that are a mix of past exam questions and past lab exercises which you can use in your study for the exam. Although many these questions are from past exams some of them are of a different style to the questions in this term's exam, see the sample exam for a better reference.

Building from scratch & Design Patterns:

* [Business Rules](spec/business.md) (21T2 Final Exam)
* [Shipping Discounts](spec/shipping.md) (20T2 Final Exam)
* [Database](spec/database.md) (21T3 Final Exam)

Refactoring an existing system & Design Patterns:
* [Engineering](spec/engineering.md) (2019 Final Exam)
* [The Crown's Gambit](spec/checkers.md) (21T2 Lab 04 Exercise)
* [Shopping Refactor](spec/shopping.md) (21T2 Final Exam)
* [Friends](spec/friends.md) (21T3 Final Exam)

Generics & Iterators:
* [Set](spec/set.md) (21T2 Lab 08 Exercise)
* [Cycle](spec/cycle.md) (21T2 Final Exam)
* [Hamper](spec/hamper.md) (20T3 Final Exam)

Theory questions:
* [Multiple Choice / Short Answer Questions](spec/theory.md) (various previous exams)

## Submission

To submit, make a tag to show that your code at the current commit is ready for your submission using the command:

```bash
$ git tag -fa submission -m "Submission for Lab 10"
$ git push -f origin submission
```

Or, you can create one via the GitLab website by going to **Repository > Tags > New Tag**.

We will take the last commit on your `master` branch before the deadline for your submission.

Problems "A Visiting Calculator" and "Calculator Adapter" sourced from [School of Computer Science, University College Dublin](https://csserver.ucd.ie).
