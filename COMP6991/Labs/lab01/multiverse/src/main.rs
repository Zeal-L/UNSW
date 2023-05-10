// hmm this doesn't look right!!
struct UniverseDetails {
    universe_name: String,
    universe_winner: String,
    universe_population: u32,
}

// Method 1
// fn get_universe_details(universe_id: u32) -> Option<UniverseDetails> {
//     if universe_id % 15 == 0 {
//         return Some(UniverseDetails {
//             universe_name: "Stardew Valley".to_string(),
//             universe_winner: "Jojo Corp".to_string(),
//             universe_population: 1,
//         })
//     } else if universe_id % 3 == 0 {
//         return Some(UniverseDetails {
//             universe_name: "Star Wars".to_string(),
//             universe_winner: "The Rebellion".to_string(),
//             universe_population: 4294967295,
//         })
//     } else if universe_id % 5 == 0 {
//         return Some(UniverseDetails {
//             universe_name: "Miraculous".to_string(),
//             universe_winner: "Hawk Moth".to_string(),
//             universe_population: 22,
//         })
//     }
//     None
// }

// Method 2
// fn get_universe_details(universe_id: u32) -> Option<UniverseDetails> {
//     let name = match universe_id {
//         id if id % 15 == 0 => "Stardew Valley",
//         id if id % 3 == 0 => "Star Wars",
//         id if id % 5 == 0 => "Miraculous",
//         _ => return None,
//     };

//     let winner = match universe_id {
//         id if id % 15 == 0 => "Jojo Corp",
//         id if id % 3 == 0 => "The Rebellion",
//         id if id % 5 == 0 => "Hawk Moth",
//         _ => return None,
//     };

//     let population = match universe_id {
//         id if id % 15 == 0 => 1,
//         id if id % 3 == 0 => 4294967295,
//         id if id % 5 == 0 => 22,
//         _ => return None,
//     };

//     Some(UniverseDetails {
//         universe_name: name.to_string(),
//         universe_winner: winner.to_string(),
//         universe_population: population,
//     })
// }

fn get_universe_details(universe_id: u32) -> Option<UniverseDetails> {
    let (name, winner, population) = match universe_id {
        id if id % 15 == 0 => ("Stardew Valley", "Jojo Corp", 1),
        id if id % 3 == 0 => ("Star Wars", "The Rebellion", 4294967295),
        id if id % 5 == 0 => ("Miraculous", "Hawk Moth", 22),
        _ => return None,
    };

    Some(UniverseDetails {
        universe_name: name.to_string(),
        universe_winner: winner.to_string(),
        universe_population: population,
    })
}

fn main() {
    for id in 1..=15 {
        if let Some(details) = get_universe_details(id) {
            println!("Universe with id {id} is called {}, won by {} and has a population of {}",
                details.universe_name,
                details.universe_winner,
                details.universe_population
            );
        } else {
            println!("Universe with id {id} is unknown");
        }
    }
}
