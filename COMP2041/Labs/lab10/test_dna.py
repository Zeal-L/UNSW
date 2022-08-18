#! /usr/bin/env python3

import sys
import dna

def main():
    assert len(sys.argv) == 2, f"Usage: {sys.argv[0]} <filename>"

    DNA = dna.read_dna(sys.argv[1])

    type = dna.is_rna(DNA)
    print(f"the file {sys.argv[1]} is {type}")
    if type == "Invalid":
        return 1

    DNA = dna.clean_dna(DNA)
    print(f"There are {len(DNA)} pairs in the file")

    print("first 10 pairs:")
    for pair in DNA[:10]:
        print(f"{pair[0]} <-> {pair[1]}")

    print("last 10 pairs:")
    for pair in DNA[-10:]:
        print(f"{pair[0]} <-> {pair[1]}")

    print("the most common base is", dna.base_to_name(dna.mast_common_base(DNA)))


if __name__ == "__main__":
    main()
