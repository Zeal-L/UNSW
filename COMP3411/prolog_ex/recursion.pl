in_tree(X, tree(_, X, _)).
in_tree(X, tree(Left, Y, _)) :-
	X \= Y,
	in_tree(X, Left).
in_tree(X, tree(_, Y, Right)) :-
	X \= Y,
	in_tree(X, Right).

tree_size(empty, 0).
tree_size(tree(Left, _, Right), N) :-
	tree_size(Left, LeftSize),
	tree_size(Right, RightSize),
	N is LeftSize + RightSize + 1.

member(X, [X | _]).
member(X, [_ | Y]) :-
	member(X, Y).

conc([], X, X).
conc([A | B], C, [A | D]) :-
	conc(B, C, D).

rev([], []).
rev([A | B], C) :-
	rev(B, D),
	conc(D, [A], C).

total_cost([], 0).
total_cost([A | B], C) :-
	total_cost(B, B_cost),
	cost(A, A_cost),
	C is A_cost +  B_cost.

cost(flange, 3).
cost(nut, 1).
cost(widget, 2).
cost(splice, 2).

test(S) :- tree_size(tree(tree(empty, jack, empty), fred, tree(empty, jill, empty)), S).
