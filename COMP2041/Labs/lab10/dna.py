

import collections


def read_dna(dna_file):
    """
    Read a DNA string from a file.
    the file contains data in the following format:
    A <-> T
    G <-> C
    G <-> C
    C <-> G
    G <-> C
    T <-> A
    Output a list of touples
    [
        ('A', 'T'),
        ('G', 'C'),
        ('G', 'C'),
        ('C', 'G'),
        ('G', 'C'),
        ('T', 'A'),
    ]
    Where either (or both) elements in the string might be missing:
    <-> T
    G <->
    G <-> C
    <->
    <-> C
    T <-> A
    """
    output = []
    with open(dna_file) as f:
        for line in f.readlines():
            c = line.split('<->')
            output.append((c[0].strip(), c[1].strip()))
    return output
    


def is_rna(dna):
    """
    Given DNA in the aforementioned format,
    return the string "DNA" if the data is DNA,
    return the string "RNA" if the data is RNA,
    return the string "Invalid" if the data is neither DNA nor RNA.
    DNA consists of the following bases:
    Adenine  ('A'),
    Thymine  ('T'),
    Guanine  ('G'),
    Cytosine ('C'),
    RNA consists of the following bases:
    Adenine  ('A'),
    Uracil   ('U'),
    Guanine  ('G'),
    Cytosine ('C'),
    The data is DNA if at least 90% of the bases are one of the DNA bases.
    The data is RNA if at least 90% of the bases are one of the RNA bases.
    The data is invalid if more than 10% of the bases are not one of the DNA or RNA bases.
    Empty bases should be ignored.
    """
    allInfo = []
    for pair in dna:
        allInfo.extend((pair[0], pair[1]))
    
    
    total = 0
    check_DNA = 0
    check_RNA = 0
    for c in allInfo:
        if c == "":
            continue
        if c in 'ATGC':
            check_DNA += 1
        if c in 'AUGC':
            check_RNA += 1
        total += 1
        
    if check_DNA / total > 0.9:
        return "DNA"
    if check_RNA / total > 0.9:
        return "RNA"
    if check_DNA / total < 0.1 or check_RNA / total < 0.1:
        return "Invalid"


def clean_dna(dna):
    """
    Given DNA in the aforementioned format,
    If the pair is incomplete, ('A', '') or ('', 'G'), ect
    Fill in the missing base with the match base.
    In DNA 'A' matches with 'T', 'G' matches with 'C'
    In RNA 'A' matches with 'U', 'G' matches with 'C'
    If a pair contains an invalid base the pair should be removed.
    Pairs of empty bases should be ignored.
    """
    check_RNA = is_rna(dna) == "RNA"
    
    out = []
    for pair in dna:
        if pair[0] == "" and pair[1] == "":
            continue
        elif check_RNA and (pair[0] == "A" and pair[1] == "" or pair[0] == "" and pair[1] == "U"):
            out.append(("A", "U"))
        elif not check_RNA and (pair[0] == "A" and pair[1] == "" or pair[0] == "" and pair[1] == "T"):
            out.append(("A", "T"))
        elif check_RNA and (pair[0] == "U" and pair[1] == "" or pair[0] == "" and pair[1] == "A"):
            out.append(("U", "A"))
        elif not check_RNA and (pair[0] == "T" and pair[1] == "" or pair[0] == "" and pair[1] == "A"):
            out.append(("T", "A"))
        elif pair[0] == "G" and pair[1] == "" or pair[0] == "" and pair[1] == "C":
            out.append(("G", "C"))
        elif pair[0] == "" and pair[1] == "G" or pair[0] == "C" and pair[1] == "":
            out.append(("C", "G"))
        elif check_RNA and (pair[0] == "A" and pair[1] != "U" or pair[0] == "U" and pair[1] != "A"):
            continue
        elif not check_RNA and (pair[0] == "A" and pair[1] != "T" or pair[0] == "T" and pair[1] != "A"):
            continue
        elif pair[0] == "G" and pair[1] != "C" or pair[0] == "C" and pair[1] != "G":
            continue
        else:
            out.append(pair)
    
    return out

def mast_common_base(dna):
    """
    Given DNA in the aforementioned format,
    return the most common first base:
    eg. given:
    A <-> T
    G <-> C
    G <-> C
    C <-> G
    G <-> C
    T <-> A
    The most common first base is 'G'.
    Empty bases should be ignored.
    """
    count = collections.defaultdict(int)
    
    for pair in dna:
        if pair[0] == "":
            continue
        count[pair[0]] += 1
    return max(count, key=count.get)

def base_to_name(base):
    """
    Given a base, return the name of the base.
    The base names are:
    Adenine  ('A'),
    Thymine  ('T'),
    Guanine  ('G'),
    Cytosine ('C'),
    Uracil   ('U'),
    return the string "Unknown" if the base isn't one of the above.
    """
    if base == "A":
        return "Adenine"
    elif base == "T":
        return "Thymine"
    elif base == "G":
        return "Guanine"
    elif base == "C":
        return "Cytosine"
    elif base == "U":
        return "Uracil"
    else:
        return "Unknown"
        
