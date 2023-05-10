use rustyline::error::ReadlineError;
use rustyline::{Editor, Result};

mod die;
use die::{roll, Coin, Die};

fn main() -> Result<()> {
    let mut rl = Editor::<()>::new()?;
    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                match line.as_str() {
                    "quit" => break Ok(()),
                    // match different die rolls
                    "d2" => println!("You rolled a d2: {}", roll(Coin)),
                    "d4" => println!("You rolled a d4: {}", roll(Die::D4)),
                    "d6" => println!("You rolled a d6: {}", roll(Die::D6)),
                    "d8" => println!("You rolled a d8: {}", roll(Die::D8)),
                    "d10" => println!("You rolled a d10: {}", roll(Die::D10)),
                    "d12" => println!("You rolled a d12: {}", roll(Die::D12)),
                    "d20" => println!("You rolled a d20: {}", roll(Die::D20)),
                    _ => println!("You typed: {}", line),
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("Goodbye!");
                break Ok(());
            }
            Err(ReadlineError::Eof) => {
                println!("Goodbye!");
                break Ok(());
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break Ok(());
            }
        }
    }
}
