use itertools::Itertools;
use std::sync::{Mutex, Arc, mpsc::channel};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};

mod test;
fn main() {
    // take number from commandline arg
    // number is guaranteed to be five digits
    let input_number = std::env::args().nth(1).unwrap().parse::<u32>().unwrap();
    if !(10000..=99999).contains(&input_number) {
        panic!("Number must be five digits");
    }

    let operators = vec!['+', '-', '*', '/'];

    // let's get a massive iterator,
    // over every arrangement of
    // digits and every arrangement of operators
    let digits_operators: Vec<(Vec<i32>, Vec<char>)> = std::env::args()
        .nth(1)
        .unwrap()
        .chars()
        .map(|x| x.to_digit(10).unwrap() as i32)
        .permutations(5)
        .into_iter()
        .cartesian_product(operators.into_iter().permutations(4).into_iter())
        .collect();

    let length = digits_operators.len();
    println!("There are {length} potential combinations",);

    // you only need to change code from here onwards
    // first, split up the digits_operators into 6 vecs
    // using the chunks method

    let (sender, receiver) = channel::<(u32, u32)>();
    let mut thread_id = 0;

    for chunk in digits_operators.chunks(length / 6) {
        let sender = sender.clone();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let num_found: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
                chunk
                .into_par_iter()
                .for_each(|(digits, operators)| {
                        let res = calculate(digits.to_vec(), operators.to_vec());
                        match res {
                            Ok(count) => *num_found.lock().unwrap() += count,
                            Err(_) => (),
                        }
                    }
                );
                sender.send((thread_id, *num_found.lock().unwrap())).unwrap();
            });
        });
        thread_id += 1;
    }

    let mut total_found = 0;
    for _ in 0..6 {
        let (thread_id, num_found) = receiver.recv().unwrap();
        println!("Thread {} found {} combinations", thread_id, num_found);
        total_found += num_found;
    }
    println!("Total: {}", total_found);

}

// DO NOT MODIFY
fn calculate(digits: Vec<i32>, operators: Vec<char>) -> Result<u32, ()> {
    let num1 = digits[0];
    let num2 = digits[1];
    let num3 = digits[2];
    let num4 = digits[3];
    let num5 = digits[4];

    let op1 = operators[0];
    let op2 = operators[1];
    let op3 = operators[2];
    let op4 = operators[3];

    let result = operate(num1, num2, op1)?;
    let result = operate(result, num3, op2)?;
    let result = operate(result, num4, op3)?;
    let result = operate(result, num5, op4)?;

    let mut count = 0;

    if result == 10 {
        println!(
            "{} {} {} {} {} {} {} {} {} = 10",
            num1, op1, num2, op2, num3, op3, num4, op4, num5
        );
        count += 1;
    }

    Ok(count)
}

// DO NOT MODIFY
fn operate(num1: i32, num2: i32, op: char) -> Result<i32, ()> {
    match op {
        '+' => Ok(num1 + num2),
        '-' => Ok(num1 - num2),
        '*' => Ok(num1 * num2),
        '/' => num1.checked_div(num2).ok_or(()),
        _ => panic!("Invalid operation"),
    }
}
