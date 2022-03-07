% cons([1, 2, 3], [4, 5, 6], Result).
cons(List1, List2, Result):-
    append(List1, List2, Result).

