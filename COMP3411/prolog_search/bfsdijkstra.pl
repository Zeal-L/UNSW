% Breadth First Search, using Dijkstras Algorithm

% COMP3411/9414 Artificial Intelligence, UNSW, Alan Blair

% This is a memory-efficient implementation of BFS, which is a
% special case of Dijkstras algorithm. It is designed to find
% only one solution (which is guaranteed to be the shortest path).

% solve(Start, Solution, D, N)
% Solution is a path (in reverse order) from start node to a goal state.
% D is the depth of the path, N is the number of nodes expanded.

solve(Start, Solution, D, N)  :-
    consult(pathsearch), % head_member(), build_path()
    bfsdijkstra([[Start,Start]], [], Solution, 1, N),
    length(Solution, D1),
    D is D1 - 1.

% bfsdijkstra(Generated, Expanded, Solution, L, N)
%
% The algorithm builds a list of generated "legs" in the form
% Generated = [[Node1,Prev1],[Node2,Prev2],...,[Start,Start]]
% sorted in increasing order of path length from the start node.
% Expanded nodes are moved to a separate list.

% If the next leg to be expanded reaches a goal node,
% stop searching, build the path and return it.
bfsdijkstra([[Node,Pred]|_Generated], Expanded, Path, N, N)  :-
    goal(Node),
    build_path([[Node,Pred]|Expanded], Path).

% Take the the leg at the head of the queue and extend it,
% by generating the successors of its destination node.
% Append these new legs to the back of the queue, and keep searching.
bfsdijkstra([[Node,Pred]|Generated], Expanded, Solution, L, N) :-
    extend(Node, Generated, Expanded, NewLegs),
    M is L + 1,
    append(Generated, NewLegs, Generated1),
    bfsdijkstra(Generated1, [[Node,Pred]|Expanded], Solution, M, N).

% Find all successor nodes to this node, and check in each case
% that the new node has not previously been generated or expanded.
extend(Node, Generated, Expanded, NewLegs) :-
    % write(Node),nl,   % print nodes as they are expanded
    findall([NewNode,Node], (s(Node, NewNode, _)
    , not(head_member(NewNode, Generated))
    , not(head_member(NewNode, Expanded))
    ), NewLegs).
