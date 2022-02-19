% Problem-specific procedures for 8-Puzzle and 15-Puzzle
% Refer to Bratko Figure 12.3.

/* Problem-specific procedures for the 8-Puzzle

  Current state is represented as a list of positions of tiles
  in the form R/C, with the first item corresponding to the
  position of "empty" and the rest to those of the tiles 1-8.

Example:

          State             Representation
      +-----------+
 1    | 1   2   3 |
 2    | 4   5   6 |       [3/3, 1/1, 1/2, 1/3, 2/1, 2/2, 2/3, 3/1, 3/2]
 3    | 7   8     |
      +-----------+
        1   2   3

  Moves are handled by swapping the positions of "empty" and one of its
  neighbours.

  The 15-Puzzle is represented in an analogous way, with 4 rows and columns.
*/

% s(Node, SuccessorNode, Cost)

s([Empty|Tiles], [Tile|Tiles1], 1) :-        % All arc costs are 1
    swap(Empty, Tile, Tiles, Tiles1).        % Swap Empty and Tile in Tiles

swap(Empty, Tile, [Tile|Ts], [Empty|Ts]) :-  % Swap allowed if Man Dist = 1
    mandist(Empty, Tile, 1).

swap(Empty, Tile, [T1|Ts], [T1|Ts1]) :-
    swap(Empty, Tile, Ts, Ts1).

mandist(X/Y, X1/Y1, D) :-      % D is Manhattan Dist between two positions
    dif(X, X1, Dx),
    dif(Y, Y1, Dy),
    D is Dx + Dy.

dif(A, B, D) :-                % D is |A-B|
    D is A-B, D >= 0, !.

dif(A, B, D) :-                % D is |A-B|
    D is B-A.

goal(Pos) :-
    length(Pos,9),
    goal3(Pos).

goal(Pos) :-
    length(Pos,16),
    goal4(Pos).

goal3([3/3,1/1,1/2,1/3,2/1,2/2,2/3,3/1,3/2]).

goal4([4/4,1/1,1/2,1/3,1/4,2/1,2/2,2/3,2/4,3/1,3/2,3/3,3/4,4/1,4/2,4/3]).

% Display a solution path as a list of board positions

showsol([]).

showsol([P|L]) :-
    showsol(L),
    nl, write('----'),
    showpos(P).

% Display a board position for the 8-Puzzle (3x3)

showpos([S0,S1,S2,S3,S4,S5,S6,S7,S8]) :-
    member(R, [1,2,3]), nl,           % Order to display Row
    member(C, [1,2,3]),               % Order to display Col
    member(Tile-R/C,                  % Tile currently at position R/C
            [' '-S0,1-S1,2-S2,3-S3,4-S4,5-S5,6-S6,7-S7,8-S8]),
    write(Tile),
    fail                              % Backtrack to next position
    ;
    true.                             % All positions displayed

% Display a board position for the 15-Puzzle (4x4)

showpos([S0,S1,S2,S3,S4,S5,S6,S7,S8,S9,S10,S11,S12,S13,S14,S15]) :-
    member(R, [1,2,3,4]), nl,           % Order to display Row
    member(C, [1,2,3,4]),               % Order to display Col
    member(Tile-R/C,                    % Tile currently at position R/C
           [' '-S0,'A'-S1,'B'-S2, 'C'-S3, 'D'-S4, 'E'-S5, 'F'-S6, 'G'-S7,
            'H'-S8,'I'-S9,'J'-S10,'K'-S11,'L'-S12,'M'-S13,'N'-S14,'O'-S15]),
    write(Tile),
    fail                              % Backtrack to next position
    ;
    true.                             % All positions displayed

% Start positions, named according to the minimum number of moves

start10([4/4,1/1,1/2,1/3,1/4,2/1,2/2,2/3,2/4,4/2,3/2,3/3,3/4,3/1,4/1,4/3]). % N=        29
start12([4/4,1/1,1/2,1/3,1/4,2/1,2/3,3/2,2/4,3/1,3/3,3/4,4/3,4/1,2/2,4/2]). % N=        21
start20([3/1,1/1,1/3,2/3,1/4,2/2,1/2,3/3,2/4,2/1,3/2,4/2,3/4,4/3,4/1,4/4]). % N=       952
start30([3/3,1/2,1/4,1/3,2/4,4/1,1/1,2/3,3/4,4/2,2/1,2/2,4/4,3/2,3/1,4/3]). % N=     17297
start40([1/3,2/1,2/2,1/4,3/3,2/4,2/3,4/1,4/3,3/1,1/1,3/4,4/4,1/2,3/2,4/2]). % N=    112571
start50([2/2,4/2,2/3,1/1,3/1,1/3,4/4,2/4,2/1,1/2,1/4,3/3,3/4,4/1,3/2,4/3]). % N=  14642512
start60([3/1,1/4,4/4,1/3,4/3,3/3,2/3,4/1,4/2,3/2,2/1,1/2,3/4,2/2,2/4,1/1]). % N= 321252368
start64([1/1,4/4,4/2,2/1,4/1,3/4,2/3,2/2,3/2,3/3,1/2,1/3,1/4,4/3,2/4,3/1]). % N=1209086782


% Example query: ?- start10(Pos), solve(Pos, Sol, G, N), showsol(Sol).

% --------------------------------------------------------------------
% The rest is needed only for A*Search (To compute the heuristic)
% --------------------------------------------------------------------

% Heuristic estimate h is the sum of distances of each tile
% from its "home" position.

h(Pos, H) :-
    length(Pos, 9),
    h3(Pos,H).

h(Pos, H) :-
    length(Pos, 16),
    h4(Pos,H).

h3([_Empty|Tiles], H) :-
    goal3([_Empty1|GoalPositions]),
    totdist(Tiles, GoalPositions, D),  % Total dist from home positions
    H is D.

h4([_Empty|Tiles], H) :-
    goal4([_Empty1|GoalPositions]),
    totdist(Tiles, GoalPositions, D),  % Total dist from home positions
    H is D.

totdist([], [], 0).

totdist([Tile|Tiles], [Position|Positions], D) :-
    mandist(Tile, Position, D1),
    totdist(Tiles, Positions, D2),
    D is D1 + D2.
