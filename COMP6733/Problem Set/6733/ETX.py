import heapq

def dijkstra(graph, start):
    distances = {node: float('inf') for node in graph}
    distances[start] = 0
    queue = [(0, start)]
    while queue:
        current_distance, current_node = heapq.heappop(queue)
        if current_distance > distances[current_node]:
            continue
        for neighbor, weight in graph[current_node].items():
            distance = current_distance + weight
            if distance < distances[neighbor]:
                distances[neighbor] = distance
                heapq.heappush(queue, (distance, neighbor))

    return distances


graphPath = "graph.txt"
graph_Tmp = {}
with open(graphPath, "r") as graphFile:
    for line in graphFile:
        line = line.strip()
        line = line.split(",")
        if line[0] not in graph_Tmp:
            graph_Tmp[line[0]] = {}
        graph_Tmp[line[0]][line[1]] = float(line[2])

for key in graph_Tmp:
    for key2 in graph_Tmp[key]:
        graph_Tmp[key][key2] = 1 / float(graph_Tmp[key][key2])

graph = {}
for key in graph_Tmp:
    graph[key] = {}
    for key2 in graph_Tmp[key]:
        graph[key][key2] = graph_Tmp[key][key2] * graph_Tmp[key2][key]

visited = {}
for key in graph:
    for key2 in graph[key]:
        if (key2, key) not in visited and (key, key2) not in visited:
            visited[(key, key2)] = True
            print(f"({key}, {key2}, {graph[key][key2]:.3f})", end=", ")
print()
start_node = 'D'
end_node = 'S'

distances = dijkstra(graph, start_node)
shortest_path_distance = distances[end_node]
print(f"The shortest path distance from {start_node} to {end_node} is: {shortest_path_distance}")

path = [end_node]
current_node = end_node
while current_node != start_node:
    for neighbor, weight in graph[current_node].items():
        if distances[current_node] == distances[neighbor] + weight:
            path.append(neighbor)
            current_node = neighbor
            break

path.reverse()
print(f"The shortest path is: {path}")
