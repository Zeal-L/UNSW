#[allow(unused_imports)]
use std::cmp::max;
use std::collections::HashMap;

struct Solution {}

impl Solution {
    pub fn length_of_longest_substring(s: String) -> i32 {
        let mut count = 0;
        let mut table: HashMap<char, i32> = HashMap::new();
        let mut i = 0;
        let s: Vec<char> = s.chars().collect();
        for j in 0..s.len() {
            if table.contains_key(&s[j]) {
                i = max(*table.get(&s[j]).unwrap() + 1, i);
            }
            table.insert(s[j], j as i32);
            count = max(count, j as i32 - i as i32 + 1);
        }
        count
    }
}

fn main() {
    println!(
        "{:?}",
        Solution::length_of_longest_substring("dvdf".to_string())
    );
    println!(
        "{:?}",
        Solution::length_of_longest_substring("abcabcbb".to_string())
    );
}
