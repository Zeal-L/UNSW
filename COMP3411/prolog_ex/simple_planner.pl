% State of the robot's world = state(RobotLocation, BasketLocation, RubbishLocation)
% action(Action, State, NewState): Action in State produces NewState
% We assume robot never drops rubbish on floor and never pushes rubbish around

action( pickup,						% Pick up rubbish from floor
	state(Pos1, Pos2, floor(Pos1)),			% Before action, robot and rubbish both at Pos1
	state(Pos1, Pos2, held)).			% After action, rubbush held by robot

action( drop,						% Drop rubbish into basket
	state(Pos, Pos, held),				% Before action, robot and basket both at Pos
	state(Pos, Pos, in_basket)).			% After action, rubbish in basket

action( push(Pos, NewPos),				% Push basket from Pos to NewPos
	state(Pos, Pos, Loc),				% Before action, robot and basket both at Pos
	state(NewPos, NewPos, Loc)).			% After action, robot and basket at NewPos

action( go(Pos1, NewPos1),				% Go from Pos1 to NewPos1
	state(Pos1, Pos2, Loc),				% Before action, robot at Pos1
	state(NewPos1, Pos2, Loc)).			% After action, robot at Pos2

% plan(StartState, FinalState, Plan)

plan(State, State, []).				% To achieve State from State itself, do nothing

plan(State1, GoalState, [Action1 | RestofPlan]) :-
	action(Action1, State1, State2),		% Make first action resulting in State2
	plan(State2, GoalState, RestofPlan). 		% Find rest of plan

% Iterative deepening planner
% Backtracking to "append" generates lists of increasing length
% Forces "plan" to ceate fixed length plans

id_plan(Start, Goal, Plan) :-
    append(Plan, _, _),
    plan(Start, Goal, Plan).

% This test should succeed without the neeed for iterative deepening
test1(Plan) :-
	plan(state(door, corner, floor(middle)), state(_, _, in_basket), Plan).

% This test will hit Prolog's stack size limit and cause an error
% The planer gets caught in infinite recursion 
test2(Plan) :-
	plan(state(door, corner, floor(middle)), state(door, corner1, in_basket), Plan).

% Iterative deeepning allows the planner to find a shortest length plan.
test3(Plan) :-
	id_plan(state(door, corner, floor(middle)), state(door, corner1, in_basket), Plan).