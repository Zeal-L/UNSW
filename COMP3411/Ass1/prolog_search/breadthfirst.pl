% breadthfirst.pl

% Breadth First Search

% COMP3411/9414/9814 Artificial Intelligence, UNSW, Alan Blair

% solve(Start, Solution, D, N)
% Solution is a path (in reverse order) from start node to a goal state.
% D is the depth of the path, N is the number of nodes expanded.

solve(Start, Solution, D, N)  :-
    breadthfirst([[Start]], Solution, 1, N),
    length(Solution, D1),
    D is D1 - 1.

% breadthfirst([Path1, Path2, ...], Solution, L, N)
%
% Store the paths generated but not yet expanded in a queue,
% sorted in order of increasing path depth (number of nodes).
% Each path is a list of nodes in reverse order,
% with the start node at the back end of the list.

% If the next path to be expanded reaches a goal node,
% return this path.
breadthfirst([[Node|Path]|_], [Node|Path], N, N) :-
    goal(Node).

% Take the path at the front of the queue and extend it,
% by adding successors of its head node. Append these newly
% created paths to the back of the queue, and keep searching.
breadthfirst([Path|Paths], Solution, L, N)  :-
    extend(Path, NewPaths),
    M is L + 1,
    append(Paths, NewPaths, Paths1),
    breadthfirst(Paths1, Solution, M, N).

% Find all successor nodes to this node, and check in each case
% that the new node does not already occur along the path.
extend([Node|Path], NewPaths)  :-
    % write(Node),nl,   % print nodes as they are expanded
    findall([NewNode,Node|Path], (s(Node, NewNode, _)
    , not(member(NewNode, [Node|Path])) % exclude repeated states
    ), NewPaths).
