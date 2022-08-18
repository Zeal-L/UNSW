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

def check_visited(graph, node):
    return all(node != path[-1] for path in graph)

inputs = [line.strip() for line in open(argv[1]) if len(line.strip()) == len(argv[2])]

bfs = [[argv[2]]]

while True:
    new_bfs = []
    for path in bfs:
        for line in inputs:
            if line not in path and check_onesie(line, path[-1]):
                temp = path.copy()
                temp.append(line)
                if check_visited(new_bfs, line):
                    new_bfs.append(temp)
                if line == argv[3]:
                    for t_line in temp:
                        print(t_line)
                    # print(len(temp))
                    exit(0)
    if bfs != new_bfs:
        bfs = new_bfs
    else:
        break
    # print(bfs, '\n', len(bfs))

print('No solution')