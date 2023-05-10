use std::cell::Cell;

fn main() {
    // Q) what is the type of my_cell
    // A) Cell<i32>

    // Q) is the my_cell type a mutable type?
    // A) TODO: write your answer here
    let my_cell = Cell::new(5);

    // Q) what are the parameters of the set method below?
    // A) TODO: write your answer here

    // Q) why does set not require a mutable reference?
    // A) TODO: write your answer here
    my_cell.set(6);

    // Q) what is interior mutability?
    // A) TODO: write your answer here

    // Q) what benefits do we as programmers get from interior mutability?
    // A) TODO: write your answer here

    // Q) Is cell Safe? Why or why not?
    // A) TODO: write your answer here

    // Q) Is it possible for Cell to be used in multiple threads? Why or why not?
    // A) TODO: write your answer here

    // Q) What is a good use case for Cell?
    // A) TODO: write your answer here

    // Q) What is the difference between Cell and RefCell?
    // A) TODO: write your answer here

    // Q) Did you find any other interesting observations?
    // A) TODO: write your answer here
}
