use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

/// Takes in a max value and returns a random number between 1 and max
// DO NOT MODIFY
fn get_random_value(max: u8) -> u8 {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    rng.gen_range(1..=max)
}

pub enum Die {
    D4,
    D6,
    D8,
    D10,
    D12,
    D20,
}

pub struct Coin;


// MODIFY/ADD BELOW HERE ONLY

pub trait Rollable {
    fn roll(&self) -> u8;
}

impl Rollable for Die {
    fn roll(&self) -> u8 {
        let max = match &self {
            Die::D4 => 4,
            Die::D6 => 6,
            Die::D8 => 8,
            Die::D10 => 10,
            Die::D12 => 12,
            Die::D20 => 20,
        };
        get_random_value(max)
    }
}

impl Rollable for Coin {
    fn roll(&self) -> u8 {
        get_random_value(2)
    }
}

pub fn roll<T: Rollable>(item: T) -> u8 {
    item.roll()
}


