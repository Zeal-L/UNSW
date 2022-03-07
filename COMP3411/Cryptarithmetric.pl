sum(List1,List2,SumList) :-
    append(List1,List2,List3),
    append(List3,SumList,AllList),
    assign([0,1,2,3,4,5,6,7,8,9],AllList),
    not_zero(List1),
    not_zero(List2),
    add_zero(List1,List1Z),
    add_zero(List2,List2Z),
    add_zero(SumList,SumListZ),
    name(Num1,List1Z),
    name(Num2,List2Z),
    name(SumNum,SumListZ),
    SumNum is Num1+Num2,
    !.

remove(X,[X|Xs],Xs).
remove(X,[Y|Ys],[Y|Res]):-
    remove(X,Ys,Res).

assign(Digits,[X|Tail]) :-
    nonvar(X),
    !,
    assign(Digits,Tail).
assign(Digits,[X|Tail]) :-
    remove(X,Digits,D1),
    assign(D1,Tail).
assign(_,[]) :-
    !.

add_zero([X|Tail1],[Y|Tail2]) :-
    !,
    Y is X+48,
    add_zero(Tail1,Tail2).
add_zero([],[]) :-
    !.

not_zero([Head|Tail]) :-
    not(Head=0).

% sum([S,E,N,D],[M,O,R,E],[M,O,N,E,Y]).