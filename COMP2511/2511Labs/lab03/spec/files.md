## Lab 03 - Core Exercise - Files 📨

Inside `src/unsw`, there is a folder `archaic_fs` and `test` that mocks a very simple file system and tests it respectively. Three tests are already written in there. `archaic_fs` simulates a 'linux' like [inode](https://en.wikipedia.org/wiki/Inode) system. You do not need to understand how it works under the hood (it simply mocks the typical linux commands). The code is also arguably written quite poorly, and in later weeks we will look at refactoring it.

The following commands are available:

| Function | Behaviour | Exceptions |
| -------- | --------- | ---------- |
| <code>cd(path)</code> | <a href="https://man7.org/linux/man-pages/man1/cd.1p.html">Change Directory</a> | <ul><li>Throws <code>UNSWNoSuchFileException</code> if a part of the path cannot be found</li></ul> | 
| <code>mkdir(path, createParentDirectories, ignoreIfExists)</code> | <a href="https://man7.org/linux/man-pages/man1/mkdir.1.html">Make Directory</a> | <ul><li>Throws <code>UNSWFileNotFoundException</code> if a part of the path cannot be found and <code>createParentDirectories</code> is false</li><li>Throws <code>UNSWFileAlreadyExistsException</code> if the folder already exists and <code>ignoreIfExists</code> is false</li></ul> |
| <code>writeToFile</code> | Writes <code>content</code> to a file at <code>path</code><ul><li>Options are a EnumSet of FileWriteOptions, e.g. <code>EnumSet.of(FileWriteOptions.APPEND, FileWriteOptions.CREATE)</code></li><li>The full set is <code>CREATE</code>,<code>APPEND</code>,<code>TRUNCATE</code>,<code>CREATE_IF_NOT_EXISTS</code></li></ul> | <ul><li>Throws <code>UNSWFileNotFoundException</code> if the file cannot be found and no creation options are specified</li><li>Throws <code>UNSWFileAlreadyExistsException</code> if the file already exists and <code>CREATE</code> is true.</li></ul>
| <code>readFromFile(path)</code> | Returns the content for a given file. | <ul><li>Throws <code>UNSWFileNotFoundException</code> if the file cannot be found</code> |  

Your task is to:
1. Create the `UNSWFileNotFoundException` and `UNSWFileAlreadyExistsException`, `UNSWNoSuchFileException` exception types in the `exceptions` package. They can simply inherit their Java counterparts (`java.io.FileNotFoundException`, `java.nio.file.FileAlreadyExistsException` and `java.nio.file.NoSuchFileException`)
2. Complete the suite of integration tests for the system. You will need at least 80% code coverage (see below). Make sure to test both success and error conditions.

### Coverage Checking

For this exercise, we require that your JUnit tests give at least 80% coverage on your code. In this course we will be using a coverage checker called **Gradle**. Gradle also allows you to see the results of your tests against your code, including test failures. **We use Gradle version 5.4.1** in this course (not the latest version).

Download the zip file from (download should start automatically): [https://gradle.org/next-steps/?version=5.4.1&format=bin](https://gradle.org/next-steps/?version=5.4.1&format=bin)

You should follow the installation instructions provided: [https://gradle.org/install/#manually](https://gradle.org/install/#manually)

For Linux users, note that you may have to edit the ~/.bashrc file to permanently change the PATH variable by appending the line:
export PATH=$PATH:/opt/gradle/gradle-5.4.1/bin

Then in the root directory of your repository run the following command.

<table>
<tr>
<td>

If you are working LOCALLY:

```bash
$ gradle test
```

</td>
<td>

If you are working on CSE:

```bash
$ 2511 gradle test
```

</td>
</tr>
</table>

The coverage checking report will be in: [build/reports/jacoco/test/html/index.html](build/reports/jacoco/test/html/index.html)

The test report will be in: [build/reports/tests/test/index.html](build/reports/tests/test/index.html)

You can also run `bash extract_coverage.sh` which will extract the coverage from the HTML and print it out.
