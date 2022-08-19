## Week 04 - Choice Blogging - Too Tightly Coupled

### Task 1

Below is some python code used by COMP2511 staff to extract marks from a spreadsheet.

```python
import gspread
google_sheet = gspread.service_account('creds.json')
sheet = gc.open('COMP2511 22T2 Marking')

marks1 = sheet.worksheets()[1]
marks2 = sheet.worksheets('marks')
```

`marks1` accesses the marks tab of the spreadsheet by reading list of sheets, and accessing the item at index 1 in the list (see below).

<img src="imgs/marks.png" />

`marks2` accesses the relevant tab by using a method of the sheet object to lookup the marks tab by name.

**Out of `marks1` or `marks2`, which do you think is more robust? Why? Write the answer in your blog post.**

### Task 2

Tight coupling causes problems in all sorts of design - not just software. Your task is to research into an example of coupling in real life - can be to do with software design or something else entirely, and write a blog post about it. In your blog post you should include:
* The area/topic of discussion/who was involved;
* What was tightly coupled, and why;
* What problems it caused; and
* If applicable, how the design could have been improved.

Make your blog post public and post it in the forum under the Blogging megathread. Read through 2 other people's posts and leave a comment on the thread providing them with some feedback.