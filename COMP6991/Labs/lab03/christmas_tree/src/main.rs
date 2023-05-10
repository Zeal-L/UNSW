use serde::Deserialize;
use std::collections::VecDeque;
use std::io;

#[derive(Debug, Deserialize)]
enum Instruction {
    Set(i32),
    Left,
    Right,
    Reset,
}

#[derive(Debug)]
struct Light {
    left: Option<Box<Light>>,
    right: Option<Box<Light>>,
    brightness: i32,
}

impl Clone for Light {
    fn clone(&self) -> Self {
        Light {
            left: self.left.clone(),
            right: self.right.clone(),
            brightness: self.brightness,
        }
    }
}


fn get_instructions_from_stdin() -> VecDeque<Instruction> {
    let mut instructions = String::new();
    io::stdin().read_line(&mut instructions).unwrap();
    ron::from_str(&instructions).unwrap()
}

fn get_average_brightness(head: &mut Box<Light>) -> i32 {
    let mut sum = 0;
    let mut count = 0;
    let mut curr = head;
    let mut stack = Vec::new();
    stack.push(curr);
    while !stack.is_empty() {
        curr = stack.pop().unwrap();
        sum += curr.brightness;
        count += 1;
        if curr.left.is_some() {
            stack.push(curr.left.as_mut().unwrap());
        }
        if curr.right.is_some() {
            stack.push(curr.right.as_mut().unwrap());
        }
    }
    sum / count
}

fn main() {
    let template = Light {
        left: None,
        right: None,
        brightness: 0,
    };
    let mut head = Box::new(template.clone());
    let mut curr = &mut head;
    for instruction in get_instructions_from_stdin() {
        match instruction {
            Instruction::Set(brightness) => {
                curr.brightness = brightness;
            }
            Instruction::Left => {
                curr.left = Some(Box::new(template.clone()));
                curr = curr.left.as_mut().unwrap();
            }
            Instruction::Right => {
                curr.right = Some(Box::new(template.clone()));
                curr = curr.right.as_mut().unwrap();
            }
            Instruction::Reset => {
                curr = &mut head;
            }
        }
    }
    // println!("{head:?}");
    println!("{}", get_average_brightness(&mut head));
}
