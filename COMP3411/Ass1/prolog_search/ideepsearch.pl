% Iterative Deepening (Depth First) Search

% COMP3411/9414/9814 Artificial Intelligence, UNSW, Alan Blair

% solve(Node, Solution, D, N)
% Solution is a path (in reverse order) from Start to a goal state
% D is the depth of the path, N is the number of nodes expanded.

solve(Node, Solution, D, N)  :-
    nb_setval(counter,0),
    ideepsearch([], Node, 0, Solution),
    nb_getval(counter,N),
    length(Solution, D1),
    D is D1 - 1.

% Perform a series of depth-limited searches with increasing depth.
ideepsearch(Path, Node, D, Solution) :-
    depthlim(Path, Node, D, Solution).

ideepsearch(Path, Node, D, Solution) :-
    D1 is D + 1,
    write(D1),nl,
    ideepsearch(Path, Node, D1, Solution).

% depthlim(Path, Node, D, Solution)
% Use depth first search to look for a solution recursively,
% up to the specified depth limit (D).

% If the next node to be expanded is a goal node, append it to
% the current path and return this path.
depthlim(Path, Node, _D, [Node|Path])  :-
    goal(Node).

% Otherwise, use Prolog backtracking to explore all successors
% of the current node, in the order returned by s.
% Keep searching until goal is found, or depth limit is reached.
depthlim(Path, Node, D, Sol)  :-
    D1 is D - 1,
    D1 > 0,
    nb_getval(counter, N),
    N1 is N + 1,
    nb_setval(counter, N1),
    % write(Node),nl,   % print nodes as they are expanded
    s(Node, Node1, _),
    not(member(Node1, Path)),		% Prevent a cycle
    depthlim([Node|Path], Node1, D1, Sol).
