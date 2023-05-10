//! This module contains the game logic
//! And manages the game state

use adventurers_quest::quest::{BlockType, Quest, QuestEvent};
use termgame::{Controller, Game, GameEvent, KeyCode, Message, SimpleEvent};

use crate::{
    player::{Direction, Moveable, Player},
    utils::{Displayable, MapInfo, Tile},
};

/// Boundaries reserved for display areas
pub const BORDER_WIDTH: u16 = 2;
/// The maximum number of breaths the player can hold
pub const MAX_BREATH: u8 = 10;


/// This struct represents the game
pub struct MyGame {
    /// This is the player instance
    pub player: Player,
    /// This is the map instance, cataloging the map information
    pub map: Box<MapInfo>,
    /// This is the quest instance, cataloging the quest information
    pub quest: Option<Box<dyn Quest<QuestEvent>>>,
}

impl Default for MyGame {
    fn default() -> Self {
        Self {
            player: Player::default(),
            map: Box::new(MapInfo {
                map: vec![],
                width: 0,
                height: 0,
                x_offset: 0,
                y_offset: 0,
                game_width: 0,
                game_height: 0,
            }),
            quest: None,
        }
    }
}

/// This function will update the player's position on the screen
/// It will call the [`Player::check_map_bounds`] function to check if the next tile is within the map bounds
/// and then call the [`Player::move_to`] function to move the player to the next tile
///
/// # Arguments
/// * `game` - The [`Game`] instance
/// * `quest` - The [`Quest`] instance
/// * `map` - The [`MapInfo`] instance
/// * `player` - The [`Player`] instance
/// * `direction` - The [`Direction`] the player is moving to
pub fn update_player_pos(
    game: &mut Game,
    quest: &mut Option<Box<dyn Quest<QuestEvent>>>,
    map: &mut MapInfo,
    player: &mut Player,
    direction: &Direction,
) {
    if player.check_map_bounds(game, map, direction) {
        // Clean up the old position
        let x = i32::from(player.x) + map.x_offset;
        let y = i32::from(player.y) + map.y_offset;
        let old_tile = if x >= 0 && x <= map.width.into() && y >= 0 && y <= map.height.into() {
            &map.map[x as usize][y as usize]
        } else {
            &Tile::Empty
        };

        game.set_screen_char(player.x.into(), player.y.into(), old_tile.get_style());

        // Update the player's position
        player.move_to(direction);

        // Update the new position
        let new = game.get_screen_char(player.x.into(), player.y.into());
        let new = new.unwrap().character(player.icon);
        game.set_screen_char(player.x.into(), player.y.into(), Some(new));

        // Update the corresponding event
        let x = i32::from(player.x) + map.x_offset;
        let y = i32::from(player.y) + map.y_offset;
        if x >= 0 && x <= map.width.into() && y >= 0 && y <= map.height.into() {
            let new_tile = &mut map.map[x as usize][y as usize];
            // Update the player's breath counter
            match new_tile {
                Tile::Water => {
                    player.breath_counter += 1;
                }
                _ => {
                    player.breath_counter = 0;
                }
            }
            match new_tile {
                // Pick up the object if exists
                Tile::Object(_, _) => {
                    new_tile.set_object_check(false);
                }
                // Show the sign message if exists
                Tile::Sign(_) => {
                    game.set_message(Some(Message::new(new_tile.get_sign_msg())));
                }
                _ => {}
            }
            // Update the quest
            update_quest(new_tile, quest);
        }
    }
}

/// This function will update the quest based on the player's current position
/// It will call the [`Quest::register_event`] function to register the corresponding event
///
/// # Arguments
/// * `new_tile` - The [`Tile`] the player is currently on
/// * `quest` - A Option Box of [`Quest`] instance
fn update_quest(new_tile: &mut Tile, quest: &mut Option<Box<dyn Quest<QuestEvent>>>) {
    if let Some(quest) = quest {
        match new_tile {
            Tile::Sand => {
                quest.register_event(QuestEvent::WalkedOnBlock(BlockType::Sand));
            }
            Tile::Water => {
                quest.register_event(QuestEvent::WalkedOnBlock(BlockType::Water));
            }
            Tile::Grass => {
                quest.register_event(QuestEvent::WalkedOnBlock(BlockType::Grass));
            }
            Tile::Object(c, _) => {
                quest.register_event(QuestEvent::CollectItem(BlockType::Object(*c)));
            }
            _ => {}
        }
    }
}

/// This function will update the map on the screen based on the player's position amd corresponding map offset for the player
///
/// # Arguments
/// * `game` - The [`Game`] instance
/// * `map` - The [`MapInfo`] instance
/// * `player` - The [`Player`] instance
///
/// # Panics
/// This function will panic if the map block at player's position not exists,
/// but this should not happen since the player's position is always within the map bounds,
/// and the map is always generated with full blocks
pub fn update_map(game: &mut Game, map: &MapInfo, player: &Player) {
    for x in 0..map.game_width {
        for y in 0..map.game_height {
            let curr_x = i32::from(x) + map.x_offset;
            let curr_y = i32::from(y) + map.y_offset;
            if curr_x >= 0
                && curr_x <= map.width.into()
                && curr_y >= 0
                && curr_y <= map.height.into()
            {
                let curr = &map.map[curr_x as usize][curr_y as usize];
                game.set_screen_char(x.into(), y.into(), curr.get_style());
            } else {
                game.set_screen_char(x.into(), y.into(), Tile::Empty.get_style());
            }
        }
    }
    let new = game.get_screen_char(player.x.into(), player.y.into());
    let new = new.unwrap().character(player.icon);
    game.set_screen_char(player.x.into(), player.y.into(), Some(new));
}

impl Controller for MyGame {
    fn on_start(&mut self, game: &mut Game) {
        // Set the screen size
        let (width, (height, _question_box_height)) = game.screen_size();
        (self.map.game_width, self.map.game_height) =
            ((width - BORDER_WIDTH), (height - BORDER_WIDTH));
        update_map(game, &self.map, &self.player);
        update_player_pos(
            game,
            &mut self.quest,
            &mut self.map,
            &mut self.player,
            &Direction::None,
        );
    }

    fn on_event(&mut self, game: &mut Game, event: GameEvent) {
        // Check if the player has run out of breath, also reset the message box
        if let GameEvent::Key(_) = event {
            game.set_message(None);
            if self.player.breath_counter >= MAX_BREATH {
                game.end_game();
            }
        }
        // Handle Game event
        match event.into() {
            SimpleEvent::Just(KeyCode::Up) => {
                update_player_pos(
                    game,
                    &mut self.quest,
                    &mut self.map,
                    &mut self.player,
                    &Direction::Up,
                );
            }
            SimpleEvent::Just(KeyCode::Down) => {
                update_player_pos(
                    game,
                    &mut self.quest,
                    &mut self.map,
                    &mut self.player,
                    &Direction::Down,
                );
            }
            SimpleEvent::Just(KeyCode::Left) => {
                update_player_pos(
                    game,
                    &mut self.quest,
                    &mut self.map,
                    &mut self.player,
                    &Direction::Left,
                );
            }
            SimpleEvent::Just(KeyCode::Right) => {
                update_player_pos(
                    game,
                    &mut self.quest,
                    &mut self.map,
                    &mut self.player,
                    &Direction::Right,
                );
            }
            SimpleEvent::Just(KeyCode::Char('q')) => {
                if let Some(quest) = &self.quest {
                    game.set_message(Some(Message::new(quest.to_string())));
                }
            }
            SimpleEvent::Just(KeyCode::Char('r')) => {
                if let Some(quest) = &mut self.quest {
                    quest.reset();
                }
            }
            _ => {}
        }
        // Check if the player has drowned
        if self.player.breath_counter == MAX_BREATH {
            game.set_message(Some(Message::new("You Drowned :(".to_string())));
        }
    }

    fn on_tick(&mut self, _game: &mut Game) {}
}
