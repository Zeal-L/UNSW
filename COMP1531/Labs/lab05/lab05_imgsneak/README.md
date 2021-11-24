## Lab05 - Challenge Exercise - Img Sneak (3 points)

Setup a flask server `imgsneak.py` that serves a 1px x 1px transparent png at a path `/email/img.png?code=ABCDEFG`

Where `ABCDEFG` is a unique code that can be anything.

When this route is accessed (via GET method), the unique code should be printed to terminal.

During the lab demonstration, send an email (via any email account on the CSE machine) to yourself. The email should be a raw email with the following code:

```html
<img src="http://127.0.0.1/email/img.png?code=yourname" />
```

When you open the email, your running flask server should print out the code.
