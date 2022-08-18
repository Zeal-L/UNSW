#! /usr/bin/env python3

from sys import argv, stderr
import regex

regex.DEFAULT_VERSION = regex.V1

assert len(argv) == 3, f"Usage: {argv[0]} <json file> <regex file>"

json_file, regex_file = argv[1], argv[2]

try:
    with open(json_file) as json_data, open(regex_file) as regex_data:
        if regex.search(regex_data.read(), json_data.read(), timeout=5):
            # In the test suite, all files that start with "y_" should be valid.
            print(f"Valid   JSON file: {json_file}")
        else:
            # In the test suite, all files that start with "n_" should be invalid.
            print(f"Invalid JSON file: {json_file}")

except TimeoutError as e:
    # Allow a timeout error to signal that the jason file is not valid
    print(f"Invalid JSON file: {json_file}")
    # This is printed to stderr so that it is not captured by the test
    print(f"5 second time limit reached while reading {json_file}", file=stderr)
