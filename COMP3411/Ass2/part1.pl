% Zeal Liang
% z5325156
% Assignment 2 - Prolog and Machine Learning


% Question 1.1: List Processing
% Description: 
%   This predicate takes a list of integers and returns 
%   the sum of the squares of only the even numbers  
%   in the list, which are determined by mod 2.
sumsq_even(Numbers, Sum) :- 
    sumsq_even(Numbers, 0, Sum).
sumsq_even([], Acc, Sum) :-
    Sum is Acc.
sumsq_even([Head | Tail], Acc, Sum) :- 
    0 is Head mod 2,
    NewAcc is Acc + Head * Head,
    sumsq_even(Tail, NewAcc, Sum).
sumsq_even([Head | Tail], Acc, Sum) :- 
    1 is Head mod 2,
    sumsq_even(Tail, Acc, Sum).
% q1_test1 :-
%     sumsq_even([1,2,3,4,5], Sum),
%     Sum = 20.
% q1_test2 :-
%     sumsq_even([1,3,5,2,-4,6,8,-7], Sum),
%     Sum = 120.
% q1_test3 :-
%     sumsq_even([1,3,5,-7,2], Sum), Sum = 4.

% ***********************************************************************

% Question 1.2: Planning 
% Description: 
%   The predicate "id_plan" acts like an Iterative deepening planner.
%   It takes a list of states and a list of
%   goal state and returns a list of actions that 
%   can be performed in order to achieve the goal state.
%   There are a total of six different actions, 
%   each with a corresponding state change.
location(lab, mr).
location(mr, cs).
location(cs, off).
location(off, lab).

action( mc,		
	state(RLoc, RHC, SMC, MW, RCM),
	state(NewLoc, RHC, SMC, MW, RCM)) :-
		location(RLoc, NewLoc).
action( mcc,		
	state(RLoc, RHC, SMC, MW, RCM),
	state(NewLoc, RHC, SMC, MW, RCM)) :-
		location(NewLoc, RLoc).
action( puc,		
	state(cs, false, true, MW, RCM),
	state(cs, true, true, MW, RCM)).
action( dc,		
	state(off, true, true, MW, RCM),
	state(off, false, false, MW, RCM)).
action( pum,		
	state(mr, RHC, SMC, true, false),
	state(mr, RHC, SMC, true, true)).
action( dm,		
	state(off, RHC, SMC, true, true),
	state(off, RHC, SMC, false, false)).


plan(State, State, []).	
plan(State1, GoalState, [Action1 | RestofPlan]) :-
	action(Action1, State1, State2),
	plan(State2, GoalState, RestofPlan).

id_plan(Start, Goal, Plan) :-
    append(Plan, _, _),
    plan(Start, Goal, Plan).

% q2_test1 :-
%     id_plan(state(lab, false, true, false, false),
%             state(_, _, false, _, _), Plan),
%     Plan = [mc, mc, puc, mc, dc].

% q2_test2 :-
%     id_plan(state(lab, false, true, true, false),
%             state(_, _, false, false, false), Plan).

% ***********************************************************************

% Question 1.3: Inductive Logic Programming
% Use Case: 
%   inter_construction(x <- [b, c, d, e], y <- [a, b, d, f], X, Y, Z).
:- op(300, xfx, <-).
% inter_construction(C1 <- B1, C2 <- B2, C1 <- Z1B, C2 <- Z2B, C <- B) :-
%     C1 \= C2,
%     intersection(B1, B2, B),
%     gensym(z, C),
%     subtract(B1, B, B11),
%     subtract(B2, B, B12),
%     append(B11, [C], Z1B),
%     append(B12, [C], Z2B).

% ***********************************************************************

% Question 1.3 (a) Intra-construction
% Description: 
%   This operators merge the two, x, clauses, keeping the  
%   intersection and adding a new predicate, z, that  
%   distributes the differences to two new clauses.
% Use Case: 
%   intra_construction(x <- [b, c, d, e], x <- [a, b, d, f], X, Y, Z).
intra_construction(X <- B1, X <- B2, X <- B3, Z1 <- Z1B, Z1 <- Z2B) :-
    X = X,
    intersection(B1, B2, B),
    gensym(z, Z1),
    subtract(B1, B, Z1B),
    subtract(B2, B, Z2B),
    append(B, [Z1], B3).

% ***********************************************************************

% Question 1.3 (b) Absorption
% Description: 
%   This operators checks to see if the body of one
%   clause is a subset of the other. If it is, the common 
%   elements can be removed from the larger clause
%   and replaced by the head of the smaller one.
% Use Case: 
%   absorption(x <- [a, b, c, d, e], y <- [a, b, c], X, Y).

absorption(X <- B1, Y <- B2, X <- R1, Y <- B2) :-
    X \= Y,
    subset(B2, B1),
    subtract(B1, B2, T1),
    append([Y], T1, R1).

% ***********************************************************************

% Question 1.3 (c) Truncation
% Description: 
%   This operators takes two rules that have the same
%   head and simply drops the differences to leave just one rule.
%   So, the body of the new clause is just the intersection 
%   of the bodies of the input clauses
% Use Case: 
%   truncation(x <- [a, b, c, d], x <- [a, c, j, k], X).
truncation(X <- B1, X <- B2, X <- B3) :-
    X = X,
    intersection(B1, B2, B3).

