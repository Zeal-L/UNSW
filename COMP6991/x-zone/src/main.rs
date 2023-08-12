use itertools::Itertools;

fn is_shunzi(cards: &[u8]) -> bool {
    cards[0] + 1 == cards[1] && cards[1] + 1 == cards[2] && cards[0] > 10
}

fn is_kezi(cards: &[u8]) -> bool {
    cards[0] == cards[1] && cards[1] == cards[2]
}

fn is_duizi(cards: &[u8]) -> bool {
    cards[0] == cards[1]
}

fn is_yaojiu(tile: u8) -> bool {
    if tile <= 11 {
        return true;
    } else {
        match tile {
            19 | 22 | 29 | 33 | 39 => true,
            _ => false,
        }
    }
}

fn is_shunzi_with_duanyaojiu(cards: &[u8]) -> bool {
    is_shunzi(&cards) && !(is_yaojiu(cards[0]) || is_yaojiu(cards[1]) || is_yaojiu(cards[2]))
}

fn is_kezi_with_duanyaojiu(cards: &[u8]) -> bool {
    is_kezi(&cards) && !(is_yaojiu(cards[0]) || is_yaojiu(cards[1]) || is_yaojiu(cards[2]))
}

fn is_duizi_with_duanyaojiu(cards: &[u8]) -> bool {
    is_duizi(&cards) && !(is_yaojiu(cards[0]) || is_yaojiu(cards[1]))
}

fn find_three_combo(cards: &mut Vec<u8>, rule: fn(&[u8]) -> bool) -> f32 {
    let mut count: f32 = 0.0;
    let mut to_remove = vec![0];

    while !to_remove.is_empty() {
        to_remove.clear();
        for comb in cards.iter().cloned().combinations(3) {
            if rule(&comb[..]) {
                count += 3.0;
                to_remove.extend_from_slice(&comb);
                break;
            }
        }

        for tile in &to_remove {
            if let Some(index) = cards.iter().position(|&x| x == *tile) {
                cards.remove(index);
            }
        }
    }

    count
}

fn find_two_combo(cards: &[u8], rule: fn(&[u8]) -> bool) -> f32 {
    let mut count: f32 = 0.0;

    for comb in cards.iter().cloned().combinations(2) {
        if rule(&comb[..]) {
            count += 1.0;
        }
    }
    count
}

fn compute_menqianqing(cards: &[u8]) -> f32 {
    let mut count: f32 = 0.0;
    let mut cards_copy = Vec::from(cards);

    count += find_three_combo(&mut cards_copy, is_kezi);
    count += find_three_combo(&mut cards_copy, is_shunzi);
    count += find_two_combo(&cards_copy, is_duizi);

    println!("count: {}", count);
    count / 13.0 * 100.0
}

fn compute_duanyaojiu(cards: &[u8]) -> f32 {
    let mut count: f32 = 0.0;
    let mut cards_copy = Vec::from(cards);

    count += find_three_combo(&mut cards_copy, is_kezi_with_duanyaojiu);
    count += find_three_combo(&mut cards_copy, is_shunzi_with_duanyaojiu);
    count += find_two_combo(&cards_copy, is_duizi_with_duanyaojiu);

    println!("count: {}", count);
    count / 13.0 * 100.0
}

fn main() {
    let cards = vec![0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 23, 23];
    let cards2 = vec![18, 18, 18, 12, 12, 12, 13, 13, 13, 3, 3, 14, 15];
    let cards3 = vec![0, 1, 2, 12, 14, 16, 22, 24, 26, 32, 34, 34, 13];

    let completion = compute_menqianqing(&cards);
    println!("门前清 几率: {:.0}%", completion);

    let completion2 = compute_duanyaojiu(&cards);
    println!("断幺九 几率: {:.0}%", completion2);
}
