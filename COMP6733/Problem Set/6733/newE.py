# 从key出到value的最短路径

# new_graph = {D:{A:0.3,C:0.5,E:0.75},A:{B:0.35,C:0.9,D:0.9},B:{A:0.75,C:0.9,S:0.7},C:{A:0.8,B:0.9,D:0.6,E:0.75,F:0.9,S:0.2},E:{C:0.7,D:0.75,F:0.85},F:{C:0.9,E:0.3,S:0.65},S:{B:0.9,C:0.2,F:0.75}}

import sys


class edge:

    def __init__(self, point1, point2):
        self.point1 = point1

        self.point2 = point2

        self.cost = 0

    def update_cost(self, cost):
        self.cost = cost

    def get_cost(self):
        return self.cost

    def get_points(self):
        return self.point1, self.point2

    def max_cost(self):
        self.cost = 100000000

    def show(self):
        print(self.point1, self.point2, self.cost)


def new_graph_fun(graph):
    graph2 = []

    for i in list(graph.keys()):

        for j in list(graph[i].keys()):

            # 检查list里头是否有相同key的结构

            have_it = check_new_graph(graph2, i, j)

            # 有相同结构就跳过

            if have_it == True:
                continue

            graph2.append(edge(i, j))

            graph2[-1].update_cost(one_cost(i, j))

    return graph2


# point1 = Struct(


def check_new_graph(graph2, i, j):
    # True 代表有相同的结构

    for i in graph2:

        if i.get_points() == (i, j) or i.get_points() == (j, i):
            return True

    return False


def one_cost(start, end):
    from_path = new_graph[start][end]

    end_path = new_graph[end][start]

    return round(1 / (from_path) * 1 / (end_path), 8)


# 定义图结构

new_graph = {

    'D': {'A': 0.3, 'C': 0.5, 'E': 0.75},

    'A': {'B': 0.35, 'C': 0.9, 'D': 0.9},

    'B': {'A': 0.75, 'C': 0.9, 'S': 0.7},

    'C': {'A': 0.8, 'B': 0.9, 'D': 0.6, 'E': 0.75, 'F': 0.9, 'S': 0.2},

    'E': {'C': 0.7, 'D': 0.85, 'F': 0.85},

    'F': {'C': 0.9, 'E': 0.3, 'S': 0.65},

    'S': {'B': 0.9, 'C': 0.2, 'F': 0.75}

}


# 运行Dijkstra算法并打印最小损耗路径和损耗数值


def dijkstra(graph, start, end):
    # 创建距离字典，并初始化所有节点的距离为无穷大

    distances = {node: sys.maxsize for node in graph}

    # 起始节点的距离设为0

    distances[start] = 0

    # 创建空的前驱字典

    predecessors = {}

    while graph:

        # 找到距离最小的未访问节点

        current_node = min(graph, key=distances.get)

        # 更新与当前节点相邻节点的距离

        for edge in graph[current_node]:

            neighbor = edge.get_points()[1]

            distance = distances[current_node] + edge.get_cost()

            if distance < distances[neighbor]:
                distances[neighbor] = distance

                predecessors[neighbor] = current_node

        # 从图中移除已访问的节点

        graph.pop(current_node)

    # 构建最小cost路径

    path = []

    node = end

    while node != start:

        predecessor = predecessors.get(node)

        if predecessor is None:
            return None  # 无法到达目标节点

        path.insert(0, (predecessor, node))

        node = predecessor

    return path, distances[end]


edges = new_graph_fun(new_graph)

graph = {}

for edge in edges:
    edge.show()
    point1, point2 = edge.get_points()

    if point1 not in graph:
        graph[point1] = []

    graph[point1].append(edge)

# shortest_path, total_cost = dijkstra(new_graph, 'S', 'D')

# print("最小损耗路径:", shortest_path)

# print("损耗数值:", total_cost)


# 运行Dijkstra算法并打印最小cost路径和损耗数值

start_node = 'S'

end_node = 'D'

shortest_path, total_cost = dijkstra(graph, start_node, end_node)

if shortest_path is None:

    print("无法到达目标节点")

else:

    print("最小cost路径:", shortest_path)

    print("总损耗数值:", total_cost)



