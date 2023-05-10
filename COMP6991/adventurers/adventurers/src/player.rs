//! This module contains the player struct and its ability to move

use crate::{
    my_game::{update_map, BORDER_WIDTH},
    utils::{MapInfo, Tile},
};
use termgame::Game;

/// This enum represents the direction the player can move to
#[derive(Debug)]
pub enum Direction {
    Up,
    Down,
    Left,
    Right,
    None,
}

/// This struct represents the player
#[derive(Debug)]
pub struct Player {
    /// The x coordinate of the player
    pub x: u16,
    /// The y coordinate of the player
    pub y: u16,
    /// The icon of the player
    pub icon: char,
    /// The breath counter of the player, will increase by 1 every time it moves on [`Tile::Water`], and reset to 0 when it moves on any other tiles
    pub breath_counter: u8,
}

impl Default for Player {
    fn default() -> Self {
        Self {
            x: 2,
            y: 2,
            icon: '♟',
            breath_counter: 0,
        }
    }
}

/// This trait represents the player's ability to move
/// It contains the functions to move the player
/// and check if the next tile is within the map bounds
/// Also it can change the map offset and the whole map
pub trait Moveable {
    /// Move the player to the next tile
    /// which is to change the player's x and y coordinates
    /// This function will not check if the next tile is within the map bounds
    /// or if the next tile is unblocked
    /// It will only move the player to the next tile
    ///
    /// # Arguments
    /// * `direction` - The direction the player is moving to
    fn move_to(&mut self, direction: &Direction);

    /// Check if the next tile is within the map bounds
    /// If it is, return true
    /// Meanwhile, it also updates the map offset and the whole map
    /// This function will call `check_unblocked` to check if the next tile is unblocked
    ///
    /// # Arguments
    /// * `game` - The game instance
    /// * `map` - The map instance
    /// * `direction` - The direction the player is moving to
    ///
    /// # Returns
    /// * `bool` - Whether the next tile is within the map bounds
    fn check_map_bounds(
        &mut self,
        game: &mut Game,
        map: &mut MapInfo,
        direction: &Direction,
    ) -> bool;

    /// Check if the next tile is unblocked
    /// If it is, return true
    /// Meanwhile, it also updates the player's breath counter
    /// and picks up items
    ///
    /// # Arguments
    /// * `map` - The map instance
    /// * `next_x` - The x coordinate of the next tile
    /// * `next_y` - The y coordinate of the next tile
    ///
    /// # Returns
    /// * `bool` - Whether the next tile is unblocked
    fn check_unblocked(&mut self, map: &MapInfo, next_x: i32, next_y: i32) -> bool;
}

impl Moveable for Player {
    fn move_to(&mut self, direction: &Direction) {
        match direction {
            Direction::Up => self.y -= 1,
            Direction::Down => self.y += 1,
            Direction::Left => self.x -= 1,
            Direction::Right => self.x += 1,
            Direction::None => {}
        }
    }

    fn check_map_bounds(
        &mut self,
        game: &mut Game,
        map: &mut MapInfo,
        direction: &Direction,
    ) -> bool {
        let (curr_x, curr_y) = (i32::from(self.x), i32::from(self.y));
        let (next_x, next_y) = match direction {
            Direction::Up => (curr_x, curr_y - 1),
            Direction::Down => (curr_x, curr_y + 1),
            Direction::Left => (curr_x - 1, curr_y),
            Direction::Right => (curr_x + 1, curr_y),
            Direction::None => (curr_x, curr_y),
        };

        if next_x < BORDER_WIDTH.into()
            || next_y < BORDER_WIDTH.into()
            || next_x >= (map.game_width - BORDER_WIDTH).into()
            || next_y >= (map.game_height - BORDER_WIDTH).into()
        {
            match direction {
                Direction::Up => {
                    map.y_offset -= 1;
                    self.y += 1;
                    update_map(game, map, self);
                    return self.check_unblocked(map, curr_x, curr_y);
                }
                Direction::Down => {
                    map.y_offset += 1;
                    self.y -= 1;
                    update_map(game, map, self);
                    return self.check_unblocked(map, curr_x, curr_y);
                }
                Direction::Left => {
                    map.x_offset -= 1;
                    self.x += 1;
                    update_map(game, map, self);
                    return self.check_unblocked(map, curr_x, curr_y);
                }
                Direction::Right => {
                    map.x_offset += 1;
                    self.x -= 1;
                    update_map(game, map, self);
                    return self.check_unblocked(map, curr_x, curr_y);
                }
                Direction::None => {}
            }
        }

        self.check_unblocked(map, next_x, next_y)
    }

    fn check_unblocked(&mut self, map: &MapInfo, next_x: i32, next_y: i32) -> bool {
        let x = next_x + map.x_offset;
        let y = next_y + map.y_offset;
        if x >= 0 && x <= map.width.into() && y >= 0 && y <= map.height.into() {
            let tile = &map.map[x as usize][y as usize];
            !matches!(tile, Tile::Barrier)
        } else {
            true
        }
    }
}
