#! /usr/bin/env python3

from sys import argv  

def check_onesie(a, b):
    count = 0
    for i in range(len(a)):
        if a[i] != b[i]:
            count += 1
        if count > 1:
            return False
    return count == 1

def BFS(graph):
    queue = [argv[2]]
    seen = {argv[2]}
    paths = {argv[2]:None} 
    while (queue):
        vertex = queue.pop(0)
        if not graph.get(vertex):
            return None
        nodes = graph[vertex]
        for node in nodes:
            if node not in seen:
                queue.append(node)
                seen.add(node)
                paths[node] = vertex
    return paths

inputs = [line.strip() for line in open(argv[1]) if len(line.strip()) == len(argv[2])]

g = {}


for line_i in inputs.copy():
    for line_j in inputs:
        if check_onesie(line_i, line_j):
            tempA = g.get(line_i, set())
            g[line_i] = tempA.union({line_j})
            tempB = g.get(line_j, set())
            g[line_j] = tempB.union({line_i})
    inputs.remove(line_i)

path = BFS(g)

if path is None:
    print('No solution')
    exit(0)

result = []

note = argv[3]

print(path)

while note != None:
    result.append(note)
    note = path[note]

for line in result[::-1]:
    print(line)
