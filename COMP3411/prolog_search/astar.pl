% A-Star Search

% COMP3411/9414/9814 Artificial Intelligence, UNSW, Alan Blair

% solve(Start, Solution, G, N)
% Solution is a path (in reverse order) from the start node to a goal state.
% G is the length of the path, N is the number of nodes expanded.

solve(Start, Solution, G, N)  :-
    consult(pathsearch), % insert_legs(), head_member(), build_path()
    h(Start,H),
    astar([[Start,Start,0,H]], [], Solution, G, 1, N).

% astar(Generated, Expanded, Solution, L, N)
%
% Generated = [[Node1,Prev1,G1,H1],[Node2,Prev2,G2,H2],...,[Start,Start,0,H0]]
%  Expanded = [[Node1,Prev1],[Node2,Prev2],...,[Start,Start]]
% Store the steps generated but not yet expanded in a queue
% sorted in increasing order of G+H.

% If the next leg to be expanded begins with a goal node,
% stop searching, build the path and return it.
astar([[Node,Pred,G,_H]|_Generated], Expanded, Path, G, N, N)  :-
    goal(Node),
    build_path([[Node,Pred]|Expanded], Path).

% Extend the leg at the head of the queue by adding the
% successors of its head node.
% Add these newly created legs to the end of the queue
astar([[Node,Pred,G,_H]| Generated], Expanded, Solution, G1, L, N) :-
    extend(Node, G, Expanded, NewLegs),
    M is L + 1,
    insert_legs(Generated, NewLegs, Generated1),
    astar(Generated1, [[Node,Pred]|Expanded], Solution, G1, M, N).

% find all successor nodes to this node, and check in each case
% that the new node has not previously been expanded
extend(Node, G, Expanded, NewLegs) :-
    % write(Node),nl,   % print nodes as they are expanded
    findall([NewNode, Node, G1, H], (s(Node, NewNode, C)
    , not(head_member(NewNode, Expanded))
    , G1 is G + C
    , h(NewNode, H)
    ), NewLegs).

% base case: insert one leg into an empty list.
insert_one_leg([], Leg, [Leg]).

% If we already knew a shorter path to the same node, discard the new one.
insert_one_leg([Leg1|Generated], Leg, [Leg1|Generated]) :-
    Leg  = [Node,_Pred, G, _H],
    Leg1 = [Node,_Pred1,G1,_H1],
    G >= G1, ! .

% Insert the new leg in its correct place in the list (ordered by G+H).
insert_one_leg([Leg1|Generated], Leg, [Leg,Leg1|Generated]) :-
    Leg  = [_Node, _Pred, G, H ],
    Leg1 = [_Node1,_Pred1,G1,H1],
    F1 is G1 + H1,
    F is G + H,
    F < F1, ! .

% Search recursively for the correct place to insert.
insert_one_leg([Leg1|Generated], Leg, [Leg1|Generated1]) :-
    insert_one_leg(Generated, Leg, Generated1).

