% Greedy (Best First) Search

% COMP3411/9414/9814 Artificial Intelligence, UNSW, Alan Blair

% solve(Start, Solution, G, N)
% Solution is a path (in reverse order) from start node to a goal state.
% G is the length of the path, N is the number of nodes expanded.

solve(Start, Solution, D, N)  :-
    consult(pathsearch), % insert_legs(), head_member(), build_path()
    h(Start,H),
    greedy([[Start,Start,H]], [], Solution, 1, N),
    length(Solution, D1),
    D is D1 - 1.

% greedy(Generated, Expanded, Solution, L, N)
%
% The algorithm builds a list of generated "legs" in the form
% Generated = [[Node1,Prev1,H1],[Node2,Prev2,H2],...,[Start,Start,H]]
% The heuristic H is stored with each leg,
% and the legs are listed in increasing order of H.
% The expanded nodes are moved to another list (H is discarded)
%  Expanded = [[Node1,Prev1],[Node2,Prev2],...,[Start,Start]]

% If the next leg to be expanded reaches a goal node,
% stop searching, build the path and return it.
greedy([[Node,Pred,_H]|_Generated], Expanded, Path, N, N)  :-
    goal(Node),
    build_path([[Node,Pred]|Expanded], Path).

% Extend the leg at the head of the queue by generating the
% successors of its destination node.
% Insert these newly created legs into the list of generated nodes,
% keeping it sorted in increasing order of H; and continue searching.
greedy([[Node,Pred,_H]|Generated], Expanded, Solution, L, N) :-
    extend(Node, Generated, Expanded, NewLegs),
    M is L + 1,
    insert_legs(Generated, NewLegs, Generated1),
    greedy(Generated1, [[Node,Pred]|Expanded], Solution, M, N).

% Find all successor nodes to this node, and check in each case
% that the new node has not previously been generated or expanded.
extend(Node, Generated, Expanded, NewLegs) :-
    % write(Node),nl,   % print nodes as they are expanded
    findall([NewNode, Node, H], (s(Node, NewNode, _C)
    , not(head_member(NewNode, Generated))
    , not(head_member(NewNode, Expanded))
    , h(NewNode, H)
    ), NewLegs).

% base case: insert one leg into an empty list.
insert_one_leg([], Leg, [Leg]).

% Insert the new leg in its correct place in the list (ordered by H).
insert_one_leg([Leg1|Generated], Leg, [Leg,Leg1|Generated]) :-
    Leg  = [_Node, _Pred, H ],
    Leg1 = [_Node1,_Pred1,H1],
    H < H1, ! .

% Search recursively for the correct place to insert.
insert_one_leg([Leg1|Generated], Leg, [Leg1|Generated1]) :-
    insert_one_leg(Generated, Leg, Generated1).
