use std::collections::HashSet;

// You will need to add lifetimes
// to this struct (and the fields)
#[derive(Debug, Default)]
pub struct Difference<'a, 'b> {
    first_only: Vec<&'a str>,
    second_only: Vec<&'b str>,
}

// You will need to add lifetimes
// to the function and the parameters
pub fn find_difference<'a, 'b>(sentence1: &'a str, sentence2: &'b str) -> Difference<'a, 'b> {

    // DO NOT MODIFY BELOW THIS LINE

    let sentence_1_words: HashSet<&str> = sentence1.split(" ").collect();
    let sentence_2_words: HashSet<&str> = sentence2.split(" ").collect();

    let mut diff = Difference::default();

    for word in &sentence_1_words {
        if !sentence_2_words.contains(word) {
            diff.first_only.push(word)
        }
    }

    for word in &sentence_2_words {
        if !sentence_1_words.contains(word) {
            diff.second_only.push(word)
        }
    }

    diff.first_only.sort();
    diff.second_only.sort();

    diff
}

// DO NOT MODIFY
// Some module tests to test our code!
// We will learn more about this next week!
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main() {
        let first_sentence = String::from("I hate the surf and the sand.");
        let second_sentence = String::from("I love the surf and the sand.");

        let first_only = {
            let third_sentence = String::from("I love the snow and the sand.");
            let diff = find_difference(&first_sentence, &third_sentence);
            diff.first_only
        };

        assert_eq!(first_only, vec!["hate", "surf"]);

        let second_only = {
            let third_sentence = String::from("I love the snow and the sand.");
            let diff = find_difference(&third_sentence, &second_sentence);
            diff.second_only
        };

        assert_eq!(second_only, vec!["surf"]);
    }
}

