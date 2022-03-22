has_borrowed(MemFamily, Title, CatNo) :-
	member(MemNo, name(MemFamily, _), _),
	loan(CatNo, MemNo, _, _),
	book(CatNo, Title, _).

later(date(Y, M, D1), date(Y, M, D2)) :-	 D1 > D2.
later(date(Y, M1, _), date(Y, M2, _)) :-	 M1 > M2.
later(date(Y1, _, _), date(Y2, _, _)) :-	 Y1 > Y2.

overdue(Today, Title, CatNo, MemFamily) :-
	loan(CatNo, MemNo, Borrowed),
	due_date(Borrowed, DueDate),
	later(Today, DueDate),
	book(CatNo, Title, _),
	member(MemNo, name(MemFamily, _), _).

due_date(date(Y, M1, D), date(Y, M2, D)) :-
	M1 < 12,
	M2 is M1 + 1.
due_date(date(Y1, 12, D), date(Y2, 1, D)) :-
	Y2 is Y1 + 1.

book(1234, "I, Robot", author("Asimov", "Isaac")).
member(3411, name("Nurke", "Fred"), "UNSW").
loan(1234, 3411, date(2022, 2, 19)).
