#give a 2d array, which is all child nodes in a decision tree, return the average of the laplace error
def laplace(array,num_node,allE):
    aver = 0
    for node in array:
        aver += (1-(max(node)+1)/(sum(node)+len(node)))*(sum(node)/num_node)
        allE.append(1-(max(node)+1)/(sum(node)+len(node)))
    return aver

if __name__ == '__main__':
    num_classes = 0

    head = [];

    headnode = input("Please input the head node: ")
    head= list(map(int, headnode.split()))
    num_classes = len(head)

    num_node = sum(head)
    array = []
    nc = 1
    while 1:
        child = []
        child_node = input(f"Please input the child {nc} node: ")
        if child_node == "":
            break
        child = list(map(int,child_node.split()))
        if len(child) != num_classes:
            print("error")
            exit()
        array.append(child)
        nc += 1

    childE = []
    laphead = laplace([head],num_node,childE)
    childE = []
    lapchild = laplace(array,num_node,childE)
    print("################################################################")
    print(f"the E for head node is: {round(laphead, 3)}")
    for i in range(len(childE)):
        print(f"the E for child node {i+1} is: {round(childE[i], 3)}")
    print(f"Average for child is: {round(lapchild, 3)}")
    if lapchild > laphead: print(f"\033[32;1m{round(lapchild, 3)} > {round(laphead, 3)}, the children should be pruned\033[0m") 
    else: print(f"\033[31;1m{round(lapchild, 3)} < {round(laphead, 3)}, the children should NOT be pruned\033[0m") 

'''
Please input the head node: 10 10 10
Please input the child 1 node: 1 7 2
Please input the child 2 node: 9 3 8
Please input the child 3 node: 
the error for head node is: 0.667
Average for child is: 0.505
0.505 < 0.667, the children should NOT be pruned
'''