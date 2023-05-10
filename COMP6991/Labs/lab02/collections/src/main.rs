use std::collections::VecDeque;
use std::collections::LinkedList;
use std::collections::HashMap;

const MAX_ITER: i32 = 300000;

fn main() {
    // Vectors
    vec_operations();

    // VecDeque
    vec_deque_operations();

    // TODO: your code here, for linked list insertions
    linked_list_operations();

    // TODO: your code here, for hashmap insertions
    hashmap_operations();

    // TODO: your text explanation to the questions in the spec
    /*
    ==== Vector ====
    insert: 7.2267ms
    remove: 2.581621s
    ==== VecDeque ====
    insert: 4.7751ms
    remove: 4.104ms
    ==== LinkedList ====
    insert: 19.9504ms
    remove: 17.3211ms
    ==== HashMap ====
    insert: 166.6146ms
    remove: 125.8486ms
     */

    /*
    1. Which collection type was the fastest for adding and removing elements?
        - VecDeque's adding is the fastest and Vector's removing is the fastest.
        - VecDeque's adding is the fastest because Its internal implementation uses
            a ring buffer data structure. This means that when adding elements,
            VecDeque can use the existing memory space without the need for
            frequent memory allocation and copy operations.
        - Vector's removing is the fastest because it is when an element is removed
            from Vector, Vector can close the hole by moving the element out of memory.
            In addition, since Vector storage elements are contiguous, the CPU
            optimizer can combine multiple contiguous memory accesses into one
            contiguous memory block access, thus reducing the number of memory accesses.

    2. Is there any significant difference between Vec and VecDeque deletion?
        - Yes, there is a significant difference.
        - In theory, deleting elements in a Vector requires moving the remaining elements,
            which results in a worst-case time complexity of O(n), although in practice
            the CPU cache is used to reduce the number of memory accesses and thus
            improve efficiency.
        - When deleting elements at one end of a VecDeque, the VecDeque can directly
            mark the first position of the array as empty without moving the elements.
            The time complexity of these operations is O(1)

    3. When would you consider using VecDeque over Vec?
        - VecDeque uses a ring buffer to store data. Thus, when it reaches its capacity,
        it can easily continue to grow without reallocating the entire array
        - So I would use it in situations where I need to add or remove elements from
        both ends of the array frequently.

    4. When would you consider using LinkedList over Vec?
        - It may be when the length of the sequence is large and then I don't need to
            do random access. Insert or delete elements frequently in the middle of the
            sequence. I would choose LinkedList.
        - Because it can do dynamic memory allocation at runtime. Unlike Vec which
            will require frequent copying to larger memory blocks as the data grows.

    5. Did the results suprise you? Why or why not?.
        - I was surprised by the speed of insertion and removal of HashMap.
            Because theoretically both operations should be O(1).
        - After researching, I found out that it is because hash tables need to
            maintain data structures such as hash buckets and hash chains, and also
            need to resolve potential hash table conflicts. That's why it's slower
            than other data structures.
        - However, I believe HashMap is still the best choice when you need to
            iently perform lookup and update operations on key-value pairs.
    */
}

/// measure the insertion and removal
/// operations of a vector
fn vec_operations() {
    let mut vec = Vec::new();

    let time_start = std::time::Instant::now();
    for i in 0..MAX_ITER {
        vec.push(i);
    }
    let time_end = std::time::Instant::now();

    println!("==== Vector ====");
    println!("insert: {:?}", time_end - time_start);

    let time_start = std::time::Instant::now();
    for _ in 0..MAX_ITER {
        vec.remove(0);
    }
    let time_end = std::time::Instant::now();

    println!("remove: {:?}", time_end - time_start);
}

/// measure the insertion and removal
/// operations of a VecDeque
fn vec_deque_operations() {
    let mut vec_deque = VecDeque::new();

    let time_start = std::time::Instant::now();
    for i in 0..MAX_ITER {
        vec_deque.push_back(i);
    }
    let time_end = std::time::Instant::now();

    println!("==== VecDeque ====");
    println!("insert: {:?}", time_end - time_start);

    let time_start = std::time::Instant::now();
    for _ in 0..MAX_ITER {
        vec_deque.pop_front();
    }
    let time_end = std::time::Instant::now();

    println!("remove: {:?}", time_end - time_start);
}

/// measure the insertion and removal
/// operations of a LinkedList
fn linked_list_operations() {
    let mut linked_list = LinkedList::new();

    let time_start = std::time::Instant::now();
    for i in 0..MAX_ITER {
        linked_list.push_back(i);
    }
    let time_end = std::time::Instant::now();

    println!("==== LinkedList ====");
    println!("insert: {:?}", time_end - time_start);

    let time_start = std::time::Instant::now();
    for _ in 0..MAX_ITER {
        linked_list.pop_front();
    }
    let time_end = std::time::Instant::now();

    println!("remove: {:?}", time_end - time_start);
}

/// measure the insertion and removal
/// operations of a HashMap
fn hashmap_operations() {
    let mut hashmap = HashMap::new();

    let time_start = std::time::Instant::now();
    for i in 0..MAX_ITER {
        hashmap.insert(i, i);
    }
    let time_end = std::time::Instant::now();

    println!("==== HashMap ====");
    println!("insert: {:?}", time_end - time_start);

    let time_start = std::time::Instant::now();
    for i in 0..MAX_ITER {
        hashmap.remove(&i);
    }
    let time_end = std::time::Instant::now();

    println!("remove: {:?}", time_end - time_start);
}