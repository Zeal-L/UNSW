% Depth First Search

% COMP3411/9414/9814 Artificial Intelligence, UNSW, Alan Blair

% solve(Node, Solution, D, N)
% Solution is a path (in reverse order) from start node to a goal state.
% D is the depth of the path, N is the number of nodes expanded.
solve(Node, Solution, D, N)  :-
    nb_setval(counter,0),
    depthfirst([], Node, Solution),
    nb_getval(counter,N),
    length(Solution, D1),
    D is D1 - 1.

% depthfirst(Path, Node, Solution)
% Use depth first search to find a solution recursively.

% If the next node to be expanded is a goal node, add it to
% the current path and return this path.
depthfirst(Path, Node, [Node|Path])  :-
    goal(Node).

% Otherwise, use Prolog backtracking to explore all successors
% of the current node, in the order returned by s.
depthfirst(Path, Node, Sol)  :-
    nb_getval(counter, N),
    N1 is N + 1,
    nb_setval(counter, N1),
    write(Node),nl,
    s(Node, Node1, _),			% Ignore cost
    not(member(Node1, Path)),		% Prevent a cycle
    depthfirst([Node|Path], Node1, Sol).
