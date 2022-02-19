% generate.pl

generate(Node, 0, Node).

generate(Start, N, Final) :-
   N > 0,
   N1 is N - 1,
   findall( NextNode, (s(Start,NextNode,_C)), NodeList),
   length(NodeList, Num),
   K is random(Num),
   nth0(K, NodeList, Node1),
   generate(Node1, N1, Final).
