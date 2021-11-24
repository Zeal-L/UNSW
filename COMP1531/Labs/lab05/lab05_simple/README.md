## Lab05 - Exercise - Simple (2 points)

This exercise should be be worked on individually.

In `server.py`, complete the flask server to store a list of names using a global variable as a list. It should have routes:
 * **`POST`** `/names/add`
   * Input: `{ name: 'example' }`
   * Output: `{}`
 * **`GET`** `/names`
   * Input: `{}`
   * Output: `{ names: [ 'example1', 'example2' ] }`
 * **`DELETE`** `/names/remove`
   * Input: `{ name: 'example' }`
   * Output: `{}`
 * **`DELETE`** `/names/clear` - clears all names, no input/output.

For example, if the following was done:
 * POST request made to `/names/add` with data `{ name: 'Asus' }`
 * POST request made to `/names/add` with data `{ name: 'Acer' }`
 * POST request made to `/names/add` with data `{ name: 'Dell' }`
 * GET request made to `/names` would return `{ names: [ 'Asus', 'Acer', 'Dell' ]}`
 * DELETE request made to `/names/remove` with data `{ name: 'Dell' }`
 * GET request made to `/names` would return `{ names: [ 'Asus', 'Acer' ]}`

Use the `requests` library (see Week 4 lectures) to write HTTP tests for the flask server in a file `simple_test.py`.

Your server will need to run on port 5000 when you submit your code - we will be relying on this for automarking.

Ensure your code is pylint compliant.
