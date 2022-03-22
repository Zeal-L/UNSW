teaches(Teacher, Student) :-
	lectures(Teacher, Subject),
	studies(Student, Subject).

more_advanced(Student1, Student2) :-
	year(Student1, Year1),
	year(Student2, Year2),
	Year1 > Year2.

lectures(ashesh, 2521).	
lectures(mike, 9417).	
lectures(claude, 3411).	
lectures(claude, 3431).	

studies(fred, 2521).
studies(jack, 3411).
studies(jill, 3431 ).
studies(jill, 9417).
studies(henry, 3431).
studies(henry, 9417).

year(fred, 1).
year(jack, 1).
year(jill, 4).
year(henry, 4).