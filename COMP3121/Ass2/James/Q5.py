import matplotlib.pyplot as plt
import networkx as nx
from networkx.drawing.nx_pydot import graphviz_layout

def slotion(A,B):
    G=nx.Graph()
    i = 1
    while i <= len(A):
        G.add_node(i,dect = str(i) + '\n'+'time ' + str(A[i-1]))
        #G.add_edge(i, i, name = str(A[i-1]), weight=A[i-1])
        i += 1
    for i in B:
        G.add_edge(i[0], i[1], name=str(i[2]), weight=i[2])

    nx.draw(G,
        edge_color='blue',
        pos=nx.circular_layout(G),
        node_color='r',
        node_size=1000,
        width=3,
    )
    node_labels = nx.get_node_attributes(G, 'dect')
    nx.draw_networkx_labels(G, pos=nx.circular_layout(G), labels=node_labels)
    edge_labels = nx.get_edge_attributes(G, 'name')
    nx.draw_networkx_edge_labels(G, pos=nx.circular_layout(G), edge_labels=edge_labels)
    plt.show()
    T=nx.minimum_spanning_tree(G)
    print(sorted(T.edges(data=True)))

    nx.draw(T,
        with_labels=True,
        edge_color='b',
        pos=nx.circular_layout(T),
        node_color='r',
        node_size=1000,
        width=3,
    )
    node_labels = nx.get_node_attributes(T, 'dect')
    nx.draw_networkx_labels(T, pos=nx.circular_layout(T), labels=node_labels)
    edge_labels = nx.get_edge_attributes(T, 'name')
    nx.draw_networkx_edge_labels(T, pos=nx.circular_layout(T), edge_labels=edge_labels)
    plt.show()

A = [5,6,5,7,8,5,7]
B = [[1,4,3],[2,3,4],[3,4,5],[5,6,3],[1,3,3]]
slotion(A,B)