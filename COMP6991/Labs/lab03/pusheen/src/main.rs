// We cannot borrow s as mutable more than once at a time ,
// The advantage of having this restriction is that Rust prevents
// data competition at compile time

// fn main() {
//     let mut vec = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

//     let a = &mut vec;
//     let b = &mut vec;

//     a.push(11);
//     b.push(12);
// }


// We can use curly brackets to create a new scope, allowing for
// multiple mutable references, just not simultaneous ones
fn main() {
    let mut vec = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    let a = &mut vec;
    {
        a.push(11);
    }
    let b = &mut vec;
    {
        b.push(12);
    }
}