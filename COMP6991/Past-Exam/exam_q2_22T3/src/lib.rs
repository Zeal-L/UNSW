#[derive(Debug, PartialOrd, Ord, PartialEq, Eq)]
pub enum DiffResult<'a> {
    LeftOnly(&'a str),
    RightOnly(&'a str),
    Both(&'a str)
}

pub fn compare_rolls<'a>(left_roll: &'a str, right_roll: &'a str) -> Vec<DiffResult<'a>> {
    let left_lines = left_roll.lines().collect::<Vec<_>>();
    let right_lines = right_roll.lines().collect::<Vec<_>>();
    let mut results = Vec::new();
    for line in &left_lines {
        if right_lines.contains(&line) {
            results.push(DiffResult::Both(line))
        } else {
            results.push(DiffResult::LeftOnly(line))
        }
    }
    for line in &right_lines {
        if !left_lines.contains(&line) {
            results.push(DiffResult::RightOnly(line))
        }
    }

    results.sort();
    return results;
}
