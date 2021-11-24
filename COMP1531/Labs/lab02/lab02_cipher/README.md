## Lab02 - Challenge Exercise - Cipher

Having recently watched [Enola Holmes](https://en.wikipedia.org/wiki/Enola_Holmes_(film)), you find yourself fascinated by codes, ciphers and cryptography and want to solve some puzzles of your own.

A transposition cipher is a type of cipher which involves permuting the text to encrypt via some physical rearrangement. One common transposition method involves writing out the message in rows, and then reading it back in columns.

Imagine you have a key `zebras` and the message you want to encrypt is `we are discovered. flee at once.`. For the purpose of this question, you can ignore all non-alphabetic characters in the message. You can assume the key will contain only lowercase letters and that the message will contain uppercase and lowercase letters. Using a columnar transposition cipher to encrypt this message, the following table is constructed:

|z|e|b|r|a|s|
|------------|-------------|----------|-----------|----------|----------|
|w|e|a|r|e|d|
|i|s|c|o|v|e|
|r|e|d|f|l|e|
|e|a|t|o|n|c|
|e|a|b|c|d|e|

Along the top of the table, the key is written. Then, in rows below the key, the message is written, with each row being the length of the key. If padding is required in the last row of the table, sequential lowercase letters of the alphabet are used to pad out the row, as many times as is necessary. This is why the last row ends with abcde.

To make the encrypted text more secure, the columns are read out in a specific order relative to the key, instead of just from left to right. The letters of the key are ordered alphabetically. This ordering defines the order in which the columns should be read out. So for our table above, the column ordering becomes `abersz`, or `521304`:

|5|2|1|3|0|4|
|------------|-------------|----------|-----------|----------|----------|
|z|e|b|r|a|s|
|w|e|a|r|e|d|
|i|s|c|o|v|e|
|r|e|d|f|l|e|
|e|a|t|o|n|c|
|e|a|b|c|d|e|

If there are duplicate letters in the key, then ties are broken by the order in which they appear in the word. So, if the key was `zoom`, the ordering would be `3120`.

To construct the encrypted text the columns are read off in the ordering defined by the key. So for our example table, the encrypted text is `evlndacdtbeseaarofocdeecewiree`.

Your job here is to write a program to perform a columnar transposition cipher. Your program should ask the user for the key and then for the text to encrypt. You will only need to encrypt the alphabetic characters, discarding any whitespace or punctuation. It should then print out the encrypted text. For example:

```python
>>> cipher('zebras' 'we are discovered. flee at once.')
evlndacdtbeseaarofocdeecewiree
```

Problem sourced from Grok Learning NCSS Challenge (Advanced), 2016.
