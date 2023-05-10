1) I saw someone's code fail to compile because they
were trying to send non-thread-safe data across threads.
How does the Rust language allow for static (i.e. at compile time)
guarantees that specific data can be sent/shared acrosss threads?

- In Rust, thread safety can be ensured using concurrency primitives, which including Mutex, Arc, RwLock ...

2) Do you have to then implement the Send and Sync traits for
every piece of data (i.e. a struct) you want to share and send across threads?

- Generally yes, but if a type only implements the Send and not the Sync, it can only be passed across threads without involving shared access. That is, the type can be safely sent to another thread, but cannot be accessed by multiple threads at the same time

3) What types in the course have I seen that aren't Send? Give one example,
and explain why that type isn't Send

- There are some types that are not Send in Rust, including some types that have internally mutable state or point to shared memory. For example, the Rc<T> type is not a Send because it contains a counter to keep track of reference counts, and this counter is variable state. Sending an Rc<T> object to another thread would cause multiple threads to access this counter at the same time, resulting in contention conditions and unsafe behavior.

4) What is the relationship between Send and Sync? Does this relate
to Rust's Ownership system somehow?

- A member that implements Sync must also implement Send, and Sync and Send are implemented based on the ownership system

5) Are there any types that could be Send but NOT Sync? Is that even possible?

- Possibly, in Rust, there are types that can be Send, but not Sync. e.g. raw pointer, unique pointer

6) Could we implement Send ourselves using safe rust? why/why not?

- No problem, as long as you make good use of the ownership system
