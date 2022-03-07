% male(Person)
% female(Person)
%
% The argument term for these predicates is a structure
% representing a person. It is in the form:
% person(FirstName, LastName)
%
male(person('Will', 'Bilson')).
male(person('Jim', 'Fried')).
male(person('Barry', 'Drake')).
female(person('Dot', 'Kanga')).
% climb(Name, Grade, FirstAscentPerson, FirstAscentDate).
%
% This predicate records the climb details.
%
climb('Happy Go Lucky', 15, person('Barry', 'Drake'), date(11, 9,1996)).
climb('High n Dry', 16, person('Jim', 'Fried'), date(1, 4,2001)).
climb('Roller', 21, person('Will', 'Bilson'), date(15, 9,2005)).
climb('Naturally', 14, person('Barry', 'Drake'), date(11,10,1997)).
climb('The Picnic', 10, person('Dot', 'Kanga'), date(14, 2,1953)).

later(date(Day1, Month, Year), date(Day2, Month, Year)) :-
    Day1 > Day2.
later(date(_, Month1, Year), date(_, Month2, Year)) :-
    Month1 > Month2.
later(date(_, _, Year1), date(_, _, Year2)) :-
    Year1 > Year2.

% solve('Roller','High n Dry').
solve(P1,P2) :-
    climb(P1, _, _, D1),
    climb(P2, _, _, D2),
    later(D1, D2).

% male(person(_, LastName)).
% climb('Roller', _, person(FirstName, LastName), _).