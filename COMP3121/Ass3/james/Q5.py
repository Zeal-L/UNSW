from matplotlib.font_manager import FontProperties
import matplotlib.pyplot as plt
import networkx as nx

# 定义图的节点和边

G = [[0,0.7,0,0.8,0.7],[0.6,0,0.8,0.9,0],[0,0.7,0,0,0],[0,0,0.8,0,0],[0.9,0,0,0.5,0]]

i = 0
while i < 5:
    j = 0
    while j < 5:
        k = 0
        while k < 5:
            G[j][k] = max(G[j][k], G[j][i]*G[i][k])
            k += 1
        j += 1
    i += 1
print(G)


'''
let dist = n * n
for i from 1 to n:
    for j from 1 to n:
        dist[i][j] = 0
for each edge w(u,v):
    dist[u][v] = w(u,v)
for k from 1 to n:
    for i from 1 to n:
        for j from 1 to n:
            dist[i][j] =max(dist[i][j] ,dist[i][k] * dist[k][j])

'''