use std::rc::Rc;

#[derive(Copy, Debug, Clone)]
pub struct InstructionNumber(u32);

impl From<u32> for InstructionNumber {
    fn from(n: u32) -> Self {
        InstructionNumber(n)
    }
}

impl From<InstructionNumber> for u32 {
    fn from(n: InstructionNumber) -> Self {
        n.0
    }
}

#[derive(Clone)]
struct Hook {
    num_left: u32,

    // TODO: figure out what type a callback might be
    // HINT: You may want to use Rc, which is a reference counted pointer
    callback: Rc<dyn Fn(&mut Cpu)>,
}

impl Hook {
    // TODO: implement the new method
    fn new(num_left: u32, callback: impl Fn(&mut Cpu) + 'static) -> Self {
        Hook {
            num_left,
            callback: Rc::new(callback),
        }
    }

    // TODO: implement a call method
    fn call(&mut self, cpu: &mut Cpu) {
        if self.num_left > 0 {
            self.num_left -= 1;
            (self.callback)(cpu);
        }
    }
}

enum Instruction<F: Fn(&Cpu) -> bool> {
    /// Do nothing
    Nop,
    /// Output the contents of our accumulator
    PrintAccumulator,
    /// JumpIfCondition
    /// InstructionNumber is 1 based
    JumpIfCondition(F, InstructionNumber),
    /// Add to the accumulator
    AddLiteral(u32),
    /// Subtract from the Accumulator
    SubLiteral(u32),
    /// Do an instruction
    /// N instructions in the future
    Callback(Hook),
    /// Exit
    Quit,
}

// You can, and should modify the Cpu struct
struct Cpu {
    current_instruction: InstructionNumber,
    accumulator: u32,
}

impl Cpu {
    fn new() -> Self {
        Cpu {
            current_instruction: InstructionNumber(0),
            accumulator: 0,
        }
    }

    fn run<F: Fn(&Cpu) -> bool>(&mut self, mut instructions: Vec<Instruction<F>>) {
        loop {
            let instruction = &mut instructions[self.current_instruction.0 as usize];
            match instruction {
                Instruction::Nop => {
                    println!("\t...no-op");
                }
                Instruction::PrintAccumulator => {
                    println!("\t...print accumulator");
                    println!("Accumulator: {}", self.accumulator);
                }
                Instruction::AddLiteral(n) => {
                    println!("\t...adding {}", n);
                    self.accumulator += *n;
                }
                Instruction::SubLiteral(n) => {
                    println!("\t...subtracting {}", n);
                    self.accumulator -= *n;
                }
                Instruction::Callback(ref mut hook) => {
                    println!("\t...callback instruction");
                    //TODO: implement this
                    hook.call(self);
                }
                Instruction::JumpIfCondition(condition, n) => {
                    println!("\t...conditional jump");
                    if condition(self) {
                        self.current_instruction = ((u32::from(*n)) - 2).into();
                    }
                }
                Instruction::Quit => {
                    break;
                }
            }
            self.current_instruction.0 += 1;
        }
    }
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<String>>();

    for arg in args {
        match arg.parse::<i32>() {
            Ok(1) => simple_test(),
            Ok(2) => simple_test_with_hook(),
            Ok(3) => complex_test(),
            Ok(_) | Err(_) => {
                panic!("Unknown test number: '{}'.", arg);
            }
        }
    }
}

fn simple_test() {
    // this test should always pass
    let mut cpu = Cpu::new();
    let instructions = vec![
        Instruction::Nop,
        Instruction::PrintAccumulator,
        Instruction::AddLiteral(1),
        Instruction::PrintAccumulator,
        Instruction::JumpIfCondition(|_| true, InstructionNumber(6)),
        Instruction::Quit,
    ];
    cpu.run(instructions);
}

fn simple_test_with_hook() {
    let mut cpu = Cpu::new();
    let instructions = vec![
        Instruction::Callback(Hook::new(2, |cpu: &mut Cpu| {
            cpu.accumulator += 6991;
        })),
        Instruction::Nop,
        Instruction::Nop,
        Instruction::JumpIfCondition(|_| true, 6.into()),
        Instruction::AddLiteral(1),
        Instruction::PrintAccumulator,
        Instruction::Quit,
    ];
    cpu.run(instructions);
}

fn complex_test() {
    // You should not need to touch any code in main
    let mut cpu = Cpu::new();
    let instructions = vec![
        Instruction::Nop,
        Instruction::PrintAccumulator,
        Instruction::AddLiteral(1),
        Instruction::Callback(Hook::new(2, |cpu: &mut Cpu| {
            cpu.accumulator += 6991;
        })),
        Instruction::Nop,
        Instruction::Nop,
        Instruction::JumpIfCondition(|cpu| cpu.accumulator <= 6991, 3.into()),
        Instruction::SubLiteral(1),
        Instruction::PrintAccumulator,
        Instruction::Quit,
    ];
    cpu.run(instructions);
}
