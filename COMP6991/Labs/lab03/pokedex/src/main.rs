use serde::Deserialize;
use std::{fs::File, io::BufReader};

////////////////////////////////////////////////////////////
// DO NOT EDIT THE BELOW CODE

#[derive(Debug, Deserialize, PartialEq, Eq)]
enum PokemonTypes {
    Bug, Dark, Dragon, Electric, Fairy, Fighting,
    Fire, Flying, Ghost, Grass, Ground, Ice,
    Normal, Poison, Psychic, Rock, Steel, Water
}

// DO NOT EDIT THIS CODE

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct PokemonNames {
    english: String,
    japanese: String,
    chinese: String,
}

// DO NOT EDIT THIS CODE

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Pokemon {
    id: u32,
    #[serde(rename = "type")]
    types: Vec<PokemonTypes>,
    name: PokemonNames
}

// DO NOT EDIT THIS CODE

type Pokedex = Vec<Pokemon>;

// DO NOT EDIT THIS CODE

fn get_pokemon(path: &str) -> Pokedex {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);

    serde_json::from_reader(reader).unwrap()
}

// DO NOT EDIT THIS CODE

fn get_pokedex_and_queries() -> (Pokedex, Vec<String>) {
    let all_pokemon = get_pokemon("pokedex.json");
    let queries: Vec<String> = std::io::stdin().lines().filter_map(|s| s.ok()).collect();

    (all_pokemon, queries)
}


/// DO NOT EDIT THE ABOVE CODE
////////////////////////////////////////////////////////////

// TODO: Below this point, you should never:
//  - Use the type "Pokemon", except as a reference.
//  - Construct or clone a "Pokemon"
//  - Use the type "String", use "str" instead.
//  - Construct or clone a String

#[derive(Debug, PartialEq, Eq)]
struct FoundPokemon<'a, 'b> {
    pokemon: &'a Pokemon,
    matching_queries: Vec<&'b str>
}


fn search_pokedex<'a, 'b>(query: &'b str, pokedex: &'a Pokedex, search_results: &mut Vec<FoundPokemon<'a, 'b>>) {
    for pokemon in pokedex {
        let contains_en = pokemon.name.english.contains(query);
        let contains_cn = pokemon.name.chinese.contains(query);
        let contains_jp = pokemon.name.japanese.contains(query);
        if contains_en || contains_cn || contains_jp {
            match search_results.iter_mut().find(|found_pokemon| found_pokemon.pokemon == pokemon) {
                Some(found_pokemon) => found_pokemon.matching_queries.push(query),
                None => search_results.push(FoundPokemon {pokemon, matching_queries: vec![query]})
            }
        }
    }
}

fn print_found_pokemon(found_pokemon: Vec<FoundPokemon>) {
    for pokemon in found_pokemon {
        let name = &pokemon.pokemon.name.english;
        print!("{name:20} : ");

        for query in pokemon.matching_queries {
            print!("{query}; ")
        }

        print!("\n");
    }
}

fn main() {
    let (pokedex, queries) =  get_pokedex_and_queries();

    let mut found_pokemon: Vec<FoundPokemon> = Vec::new();

    for query in queries.iter() {
        search_pokedex(&query, &pokedex, &mut found_pokemon);
    }

    print_found_pokemon(found_pokemon);
}
