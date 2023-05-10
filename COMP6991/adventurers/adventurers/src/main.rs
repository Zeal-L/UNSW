use adventurers_quest::quest::example_quest;
use anyhow::Result;
use std::error::Error;
use std::time::Duration;
use termgame::{run_game, GameSettings, KeyCode, SimpleEvent};

pub mod utils;
use utils::read_from_path;

pub mod my_game;
use my_game::MyGame;

pub mod player;

fn main() -> Result<(), Box<dyn Error>> {
    let mut controller = MyGame::default();

    // Read the map from the file
    let mut map_path = std::env::args()
        .nth(1)
        .unwrap_or("maps/testing_game.ron".to_string());
    map_path = format!("../{map_path}");
    controller.map = read_from_path(&map_path)?;

    // Set the quest if provided
    let quest_name = std::env::args().nth(2);
    if let Some(quest_name) = quest_name {
        controller.quest = example_quest(quest_name);
    } else {
        controller.quest = example_quest("q3".to_string());
    }

    // Start the game
    run_game(
        &mut controller,
        GameSettings::new()
            .tick_duration(Duration::from_millis(50))
            .quit_event(Some(SimpleEvent::WithControl(KeyCode::Char('c')).into())),
    )?;

    println!("Game Ended!");

    Ok(())
}
