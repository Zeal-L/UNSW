//! Utility module for the game
//! Including module to read map files

pub mod read_map {
    use anyhow::{Context, Result};
    use ron::de::from_reader;
    use serde;
    use serde::Deserialize;
    use std::{collections::HashMap, error::Error, fs::File, io::BufReader};
    use termgame::{GameColor, GameStyle, StyledCharacter};

    /// This struct represents the different types of tiles
    #[derive(Debug, Deserialize, Clone)]
    pub enum Tile {
        Grass,
        Sand,
        Rock,
        Cinderblock,
        Flowerbush,
        Barrier,
        Water,
        Sign(String),
        Object(char, #[serde(default = "default_object_bool")] bool),
        Empty,
    }

    /// Set the default value for the object check
    fn default_object_bool() -> bool {
        true
    }

    /// This trait represents the ability to be displayed on the screen
    pub trait Displayable {
        /// Return the character to be displayed
        ///
        /// # Returns
        /// * `char` - The character to be displayed
        fn get_char(&self) -> char;
        /// Return the style to be applied to the character
        ///
        /// # Returns
        /// * `Option<StyledCharacter>` - The style to be applied to the character
        fn get_style(&self) -> Option<StyledCharacter>;
        /// Set the object check
        ///
        /// # Arguments
        /// * `check` - The new value for the object check
        fn set_object_check(&mut self, check: bool);
        /// Get the sign message
        ///
        /// # Returns
        /// * `String` - The sign message
        fn get_sign_msg(&self) -> String;
    }

    impl Displayable for Tile {
        fn get_char(&self) -> char {
            match self {
                Self::Grass
                | Self::Sand
                | Self::Rock
                | Self::Cinderblock
                | Self::Flowerbush
                | Self::Barrier
                | Self::Water
                | Self::Empty => ' ',
                Self::Sign(_) => '💬',
                Self::Object(c, check) => {
                    if *check {
                        *c
                    } else {
                        ' '
                    }
                }
            }
        }
        fn get_style(&self) -> Option<StyledCharacter> {
            match self {
                Self::Grass => {
                    Some(StyledCharacter::new(self.get_char()).style(
                        GameStyle::new().background_color(Some(GameColor::Rgb(19, 161, 14))),
                    ))
                }
                Self::Sand => {
                    Some(StyledCharacter::new(self.get_char()).style(
                        GameStyle::new().background_color(Some(GameColor::Rgb(249, 241, 165))),
                    ))
                }
                Self::Rock => {
                    Some(StyledCharacter::new(self.get_char()).style(
                        GameStyle::new().background_color(Some(GameColor::Rgb(118, 118, 118))),
                    ))
                }
                Self::Cinderblock => {
                    Some(StyledCharacter::new(self.get_char()).style(
                        GameStyle::new().background_color(Some(GameColor::Rgb(231, 72, 86))),
                    ))
                }
                Self::Flowerbush => {
                    Some(StyledCharacter::new(self.get_char()).style(
                        GameStyle::new().background_color(Some(GameColor::Rgb(180, 0, 158))),
                    ))
                }
                Self::Barrier => {
                    Some(StyledCharacter::new(self.get_char()).style(
                        GameStyle::new().background_color(Some(GameColor::Rgb(255, 255, 255))),
                    ))
                }
                Self::Water => Some(
                    StyledCharacter::new(self.get_char())
                        .style(GameStyle::new().background_color(Some(GameColor::Rgb(0, 55, 218)))),
                ),
                Self::Sign(_) => Some(StyledCharacter::new('💬')),
                Self::Object(_, _) => Some(StyledCharacter::new(self.get_char())),
                Self::Empty => Some(StyledCharacter::new(self.get_char()).style(GameStyle::new())),
            }
        }

        fn set_object_check(&mut self, check: bool) {
            if let Tile::Object(_, ref mut b) = *self {
                *b = check;
            }
        }

        fn get_sign_msg(&self) -> String {
            match self {
                Self::Sign(msg) => msg.clone(),
                _ => String::new(),
            }
        }
    }

    /// A struct that holds the map information
    pub struct MapInfo {
        /// A 2D vector of [`Tile`]
        pub map: Vec<Vec<Tile>>,
        /// The width of the imported map
        pub width: u16,
        /// The height of the imported map
        pub height: u16,
        /// The x offset of the map relative to the game window
        pub x_offset: i32,
        /// The y offset of the map relative to the game window
        pub y_offset: i32,
        /// The width of the game window
        pub game_width: u16,
        /// The height of the game window
        pub game_height: u16,
    }

    /// Read a map file and return a [`MapInfo`] struct
    ///
    /// # Panics
    /// Panics if the map file is not a valid RON file
    ///
    /// # Arguments
    /// * `path` - The path to the map file
    ///
    /// # Returns
    /// * `Result<Box<MapInfo>, Box<dyn Error>>` - A [`MapInfo`] struct or an error
    pub fn read_from_path(path: &String) -> Result<Box<MapInfo>, Box<dyn Error>> {
        let file = File::open(path).with_context(|| format!("Failed to open file: {}", path))?;
        let reader = BufReader::new(file);
        let blocks: HashMap<(u16, u16), Tile> = from_reader(reader).expect("Failed to parse RON");

        let mut map = Vec::new();
        let width = *blocks.keys().map(|(x, _y)| x).max().unwrap();
        let height = *blocks.keys().map(|(_x, y)| y).max().unwrap();
        for x in 0..=width {
            let mut row = Vec::new();
            for y in 0..=height {
                let tile = blocks.get(&(x, y)).unwrap_or(&Tile::Empty);
                row.push(tile.clone());
            }
            map.push(row);
        }
        let map_info = MapInfo {
            map,
            width,
            height,
            x_offset: 0,
            y_offset: 0,
            game_width: 0,
            game_height: 0,
        };
        Ok(Box::new(map_info))
    }
}

pub use read_map::{read_from_path, Displayable, MapInfo, Tile};
