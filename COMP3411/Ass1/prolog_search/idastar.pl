% Iterative Deepening A-Star Search

% COMP3411/9414/9814 Artificial Intelligence, UNSW, Alan Blair

% solve(Start, Solution, G, N)
% Solution is a path (in reverse order) from Node to a goal state.
% G is the length of the path, N is the number of nodes expanded.
solve(Start, Solution, G, N)  :-
    nb_setval(counter,0),
    idastar(Start, 0, Solution, G),
    nb_getval(counter,N).

% Perform a series of depth-limited searches with increasing F_limit.
idastar(Start, F_limit, Solution, G) :-
    depthlim([], Start, 0, F_limit, Solution, G).

idastar(Start, F_limit, Solution, G) :-
    write(F_limit),nl,
    F_limit1 is F_limit + 2,  % suitable for puzzles with parity
    idastar(Start, F_limit1, Solution, G).

% depthlim(Path, Node, Solution)
% Use depth first search (restricted to nodes with F <= F_limit)
% to find a solution which extends Path, through Node.

% If the next node to be expanded is a goal node, add it to
% the current path and return this path, as well as G.
depthlim(Path, Node, G, _F_limit, [Node|Path], G)  :-
    goal(Node).

% Otherwise, use Prolog backtracking to explore all successors
% of the current node, in the order returned by s.
% Keep searching until goal is found, or F_limit is exceeded.
depthlim(Path, Node, G, F_limit, Sol, G2)  :-
    nb_getval(counter, N),
    N1 is N + 1,
    nb_setval(counter, N1),
    % write(Node),nl,   % print nodes as they are expanded
    s(Node, Node1, C),
    not(member(Node1, Path)),      % Prevent a cycle
    G1 is G + C,
    h(Node1, H1),
    F1 is G1 + H1,
    F1 =< F_limit,
    depthlim([Node|Path], Node1, G1, F_limit, Sol, G2).
