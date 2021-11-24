## Lab04 - Exercise - Weather (2 points)

Copy the weather data from the class account.

```bash
cp ~cs1531/public_html/21T3/weatherAUS.csv ./
```

If you are working locally, you can run the following command (replace the zID with your own).

```
scp z55555555@cse.unsw.edu.au:∼cs1531/public_html/21T3/weatherAUS.csv weatherAUS.csv
```

In `weather.py` complete function `weather` that takes in two arguments:
 1. A date in the format "DD-MM-YYYY"
 2. The name of a location e.g. "Albury"

It returns a tuple `(A, B)` where `A` is the value of how far the minimum temperature is below the average minimum across all time, for that given day, and `B` is the value of how far the maximum temperature is above the average maximum across all time, for that given day.

If an invalid (or empty) date or town is entered, the function should simply return `(None, None)`.

For example, if the MinTemp and MaxTemp of 'Albury' on '08-08-2010' is -1.3 and 12.6 respectively, and the average minimum and average maximum temperature of Albury over the entire data set is 9.5 and 22.6, the function would return `(10.8, -10.0)`

Any values in the table that are "NA" or any other invalid number do not need to be counted.

Write tests in `weather_test.py`, a file you create.

Ensure your code is pylint compliant and that your tests have 100% code coverage.
