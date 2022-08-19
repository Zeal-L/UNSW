## Lab 07 - Core/Choice Exercise - Abstract File Editors 💾

Inside the `fileEditor` package is code for an application that launches a window that allows the user to edit HTML files. This includes being able to download the raw HTML from a webpage given a URL and save that onto the local computer. For example:

<img src='imgs/img4.png' />

Inside `EditorApplication.java`, if we were to change the variable `editorType` to be `"Text Editor"`, the code would render an application which allows the user to edit files as a normal Text Editor. For example:

<img src='imgs/img5.png' />

Currently, all of the frontend code to render the elements for both types of editors is inside the constructor of `EditorApplication`. At this point in the course you probably find the code excruciatingly painful to look at.

Refactor the code to use the Abstract Factory Patten in the setup and rendering of elements for both HTML files and text files. Empty `EditorFactory`, `HTMLEditorFactory` and `TextEditorFactory` have been provided for you. Replace the existing constructor of `EditorApplication` so that it takes in an `EditorFactory` and calls all of the respective methods on to construct the elements, as well as anything else that may need doing to setup the interface. 

On completion, you should be able to run the `main` function in `EditorApplication` and the application will work as it does currently.

You will not need to write any frontend code that is not already present to complete this exercise.
