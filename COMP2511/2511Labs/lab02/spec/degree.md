## Lab 02 - Challenge Exercise - Degree Distribution 📝

In Australia, university degrees are allocated using a centralised preference system, where final high school exam marks are converted into a score in steps of 0.05 up to 99.95. A score of 99.00 indicates that the student's aggregated marks were better than 99% of their cohort.

Each degree has a certain number of available places, and accepts students until it is full. Students nominate up to nine degrees, ordered from first to last preference. They are considered in descending order of their marks, receiving an offer for the first degree in their preference list that still has available places. Each degree has a *cutoff mark*: the lowest score out of the students who received a place in that degree.

You will be given two JSON files, one containing degrees and one containing students. An example `degrees.json` is in the following format.

```javascript
[{"code": 422000, "name": "Bachelor of Arts","institution": "University of New South Wales", "places": 10},
{"code": 422300, "name": "Bachelor of Social Research and Policy","institution": "University of New South Wales", "places": 8},
{"code": 423600, "name": "Bachelor of Planning","institution": "University of New South Wales", "places": 10},
{"code": 511207, "name": "Bachelor of Arts (Media and Communications)","institution": "University of Sydney", "places": 2},
{"code": 511504, "name": "Bachelor of Commerce","institution": "University of Sydney", "places": 1},
{"code": 511795, "name": "Bachelor of Computer Science and Technology","institution": "University of Sydney", "places": 8}]
```

`students.json` is in the following format.

```javascript
[{"name": "Claudia Zingaro", "score": 84.50, "preferences": ["422300+2","511207"]},
{"name": "Ivan Connolly", "score": 91.00, "preferences": ["511207+5","511504"]},
{"name": "Jeffie Honaker", "score": 94.50, "preferences": ["511207","511504","511795"]},
{"name": "Floria Rozar", "score": 82.25, "preferences": ["422000","422300","511207","511504"]},
{"name": "Hyun Castleberry", "score": 83.15, "preferences": ["511795", "423600"]},
{"name": "Leland Acheson", "score": 81.15, "preferences": ["511207","422000"]},
{"name": "Wally Seppala", "score": 95.00, "preferences": ["511504"]},
{"name": "Cristi Authement", "score": 90.00, "preferences": ["511207"]},
{"name": "Yadira Millwood", "score": 83.15, "preferences": ["511795+2.5"]},
{"name": "Abram Bloomer", "score": 98.00, "preferences": ["511207","511795"]}]
```

Students' degree preferences are described in a semicolon-seperated list of unique degree codes ordered by preference. Preferences suffixed with `+n` indicate that the student has *flexible entry* for that degree and receives that many bonus marks when considered **for that degree only**.

Bonuses may increase a score up to a maximum of 99.95. If the bonus pushes a score sbove the cutoff mark for a degree with no places available, the lowest scoring studenti is evicted to make way, and the degree cutoff is adjusted to the next lowest score (which may be the bonus-adjusted score of the new student). The evicted student is reconsidered for other degree as an appropriate for their score and any bonuses.

In `DegreeDistribution.java`, the `distribute` method takes in two parameters: the name of the degrees JSON file and the name of the students JSON file. and returns a JSON string of the format `{"degrees": [...], "students": [...]}`.

* The array of degrees is odered lexographically by their code. Each degree has a code, a cutoff, a vacancies boolean, and the number of students offered positions in the degree.
* A list of students, ordered by their original mark to 2 decimal places, with the degree code they have been offered.

If a student does not receive a degree place, or a degree has no cutoff, you should return `-` in the relevant location.

For all parts of this question that could result in tie breaking, including offers, eviction and final output, break any mark ties in ascending alphabetical order of student names. That is, if Amy and Zoe have the same effective score for a degree, Amy should be offered before Zoe, and Zoe should be evicted before Amy.

Given the example files above, your program should produce the following:

```javascript
{"degrees": [
    {"code": 422000, "name": "Bachelor of Arts","institution": "University of New South Wales", "cutoff": 81.15, "offers": 2, "vacancies": true},
    {"code": 422300, "name": "Bachelor of Social Research and Policy","institution": "University of New South Wales", "cutoff": 86.50, "offers": 1, "vacancies": true},
    {"code": 423600, "name": "Bachelor of Planning","institution": "University of New South Wales", "cutoff": "-", "offers": 0, "vacancies": true},
    {"code": 511207, "name": "Bachelor of Arts (Media and Communications)","institution": "University of Sydney", "cutoff": 96.00, "offers": 2, "vacancies": false},
    {"code": 511504, "name": "Bachelor of Commerce","institution": "University of Sydney", "cutoff": 95.00, "offers": 1, "vacancies": false},
    {"code": 511795, "name": "Bachelor of Computer Science and Technology","institution": "University of Sydney", "cutoff": 83.15, "offers": 3, "vacancies": true}
],
"students": [
    {"name": "Abram Bloomer", "score": 98.00, "offer": 511207},
    {"name": "Wally Seppala", "score": 95.00, "offer": 511504},
    {"name": "Jeffie Honaker", "score": 94.50, "offer": 511795},
    {"name": "Ivan Connolly", "score": 91.00, "offer": 511207},
    {"name": "Cristi Authement", "score": 90.00, "offer": "-"},
    {"name": "Claudia Zingaro", "score": 84.50, "offer": 422300},
    {"name": "Hyun Castleberry", "score": 83.15, "offer": 511795},
    {"name": "Yadira Millwood", "score": 83.15, "offer": 511795},
    {"name": "Floria Rozar", "score": 82.25, "offer": 422000},
    {"name": "Leland Acheson", "score": 81.15, "offer": 422000}
]}
```

Within the two input files, you can assume that the degree codes will be unique, as are the names of students. The degree preference codes are guaranteed to be in the degrees JSON file.

Design and implement an object-oriented solution to this problem. You are given a near-complete suite of JUnit tests.

**Extension Challenge**: Determine the edge case missing from the test suite, add it in and make sure your code passes.

Problem sourced from Grok Learning NCSS Challenge (Advanced), 2017 and adapted for Java.

