## Lab 10 - Core Exercise - Graph Iterator 🔗

> ℹ️ You will need to make a **Private** (set to Course Staff can view only) Blog Post on WebCMS for this activity. Put your answers to the questions inside it.

The Iterator Pattern allows us to traverse a data structure whilst maintaining the abstraction of the data structure's underlying details. An iterator is a black-box that we can keep asking to give us elements, until it runs out. This occurs in a *linear* fashion (we ask for elements one at a time), and the Iterator Pattern hence allows us to *linearise* any data structure. 

For `Set`s, `ArrayList`s and plenty of other data structures this is all very well because the ADT itself is already linear, conceptually. But what about something that's non-linear, like a graph? So long as we have some sort of sequence to accessing elements of the data structure, we can build an iterator.

In this exercise, you will be using the Iterator Pattern to write two iterators - one which traverses a graph using **Breadth-First Search** and one that traverses a graph using **Depth-First Search**.

Inside `src/graph/Graph.java`, we have written a Generic `Graph` class which models an undirected graph using an **adjacency list** with a `HashMap`. To recall, an adjacency list stores the graph in the following format:

```
Node : [ All the nodes the node is adjacent to ]
```

### BFS

Create a new class called `BreadthFirstGraphIterator.java` that uses BFS to traverse a graph, given that graph and a starting node. Each subsequent call to the `next` method should 'tick' the BFS by one (i.e. the next element is looked at). You may not pre-traverse the graph and store the nodes to visit in an `ArrayList` or similar and simply pawn off the job to that.

BFS Pseudocode:

```
queue = []
visited = set()
while queue:
    vertex = queue.dequeue()
    visited.add(vertex)
    queue.extend(graph.get_adjacent(vertex) - visited)
```

Inside `Graph.java`, write a method called `breadthFirstIterator` which returns a new BFS iterator.

### DFS

Create a new class called `DepthFirstGraphIterator.java` that uses DFS to traverse a graph, given that graph and a starting node. Each subsequent call to the `next` method should 'tick' the DFS by one (i.e. the next element is looked at). You may not pre-traverse the graph and store the nodes to visit in an `ArrayList` or similar and simply pawn off the job to that.

Inside `Graph.java`, write a method called `depthFirstIterator` which returns a new DFS iterator.

If you need to brush up on Graphs, here are a few links to COMP2521 lectures:
* [Graph ADT](https://www.youtube.com/watch?v=4s_3uirIGM8&list=PLi2pCZz5m6GEftzPIxVH1ylwytux9WOGN&index=16)
* [Graph Implementations](https://www.youtube.com/watch?v=2hbR-aez1E4&list=PLi2pCZz5m6GEftzPIxVH1ylwytux9WOGN&index=17)
* [Graph Traversal](https://www.youtube.com/watch?v=DzdztZboQ6w&list=PLi2pCZz5m6GEftzPIxVH1ylwytux9WOGN&index=18)

Some simple tests have been provided for you inside `GraphTest.java`, they don't currently compile as the Iterator classes themselves do not exist.

The second test uses this Graph:

<img src='imgs/graph.png' width='500' />


<details>
<summary>Hints</summary>

* You will not be able to use recursion to do the DFS.
* Java provides collections which will help you with the implementation of the algorithm.

</details>

### Iterators & Iterables

Change the definition of `Graph` so that it is `Iterable`. By default, the graph will traverse itself using a BFS, starting with the first node that was added to the graph. Write a test for this that loops through a graph. 

Inside your blog post, answer the following questions:

1. Do you think making the `Graph` `Iterable` makes semantic sense? Discuss briefly, and think of both sides.
2. We could change the definition of our `Graph` so that the traversal logic is done internally, i.e:

    ```java
    public class Graph<N extends Comparable<N>> implements Iterable<N>, Iterator<N>
    ```

3. Is a `Graph` an iterator or an iterable in this case? 
4. What would the `.iterator` method return in this case?
5. There is a problem with this approach though. Inside `iterator.md`, describe a test that would cause this implementation to fail.