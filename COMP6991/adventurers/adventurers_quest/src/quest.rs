//! This module contains the all basic types and traits for quests, and provides a example function to create a quest.

use dyn_clonable::*;
use std::fmt::Display;

use crate::{
    quest_combine::{AtLeastNumQuests, ThenQuest},
    quest_single::{BlocksWalkedQuest, CollectQuest},
};

/// The type of block in the game that used by quests.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BlockType {
    Grass,
    Sand,
    Water,
    Object(char),
}

impl Display for BlockType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Grass => write!(f, "grass"),
            Self::Sand => write!(f, "sand"),
            Self::Water => write!(f, "water"),
            Self::Object(c) => write!(f, "'{}'", c),
        }
    }
}

/// The event that can be registered to a quest.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum QuestEvent {
    /// A task requires the player to walk on a block of a specific type.
    WalkedOnBlock(BlockType),
    /// A task requires the player to collect a specific type of block.
    CollectItem(BlockType),
}

/// The status of a quest. It can be either `complete` or `ongoing`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum QuestStatus {
    Complete,
    Ongoing,
}

impl From<bool> for QuestStatus {
    fn from(status: bool) -> Self {
        match status {
            true => QuestStatus::Complete,
            false => QuestStatus::Ongoing,
        }
    }
}

impl From<QuestStatus> for bool {
    fn from(status: QuestStatus) -> Self {
        matches!(status, QuestStatus::Complete)
    }
}

/// The trait for a quest. It requires the quest to be clonable
#[clonable]
pub trait Quest<QuestEvent>: std::fmt::Display + Clone {
    /// Whenever something happens, you call "register_event" to tell the quest what's happened.
    /// The quest will update its status accordingly.
    ///
    /// # Arguments
    /// * `event` - The event that happened.
    ///
    /// # Example
    /// see detailed example at following:
    /// - [`BlocksWalkedQuest::register_event`] (for a single quest)
    /// - [`CollectQuest::register_event`] (for a single quest)
    /// - [`AtLeastNumQuests::register_event`] (for a combined quest)
    /// - [`ThenQuest::register_event`] (for a combined quest)
    fn register_event(&mut self, event: QuestEvent);

    /// Reset the quest, so that players can restart.
    fn reset(&mut self);

    /// Check if the quest is complete.
    ///
    /// # Returns
    /// - [`QuestStatus::Complete`] if the quest is complete
    /// - [`QuestStatus::Ongoing`] otherwise.
    fn is_complete(&self) -> QuestStatus;
}

impl dyn Quest<QuestEvent> {
    /// Get the status of the quest in a string.
    /// It will return "✅" if the quest is complete, and " " otherwise.
    pub fn get_complete_sign(&self) -> &str {
        let status = if self.is_complete() == QuestStatus::Complete {
            "✅"
        } else {
            " "
        };
        status
    }
}

/// A function to create example quests.
///
/// # Arguments
/// * `quest_name` - The name of the quest. It can be "q1", "q2", or "q3".
///   - "q1" is a single quest.
///   - "q2" is a ThenQuest.
///   - "q3" is a AtLeastNumQuests + ThenQuest.
///
/// # Returns
/// - `Some(Box<dyn Quest<QuestEvent>>)` if the quest is created successfully.
/// - `None` otherwise.
pub fn example_quest(quest_name: String) -> Option<Box<dyn Quest<QuestEvent>>> {
    match quest_name.as_str() {
        "q1" => {
            let quest = BlocksWalkedQuest::new(BlockType::Sand, 5, 1);
            Some(Box::new(quest))
        }
        "q2" => {
            let quest1 = CollectQuest::new(BlockType::Object('x'), 5);
            let quest2 = CollectQuest::new(BlockType::Object('y'), 3);
            Some(Box::new(ThenQuest::new(quest1, quest2)))
        }
        "q3" => {
            let q1_1 = BlocksWalkedQuest::new(BlockType::Sand, 5, 1);
            let q1_2 = CollectQuest::new(BlockType::Object('x'), 1);
            let q1 = Box::new(ThenQuest::new(q1_1, q1_2));
            let q2_1 = CollectQuest::new(BlockType::Object('x'), 1);
            let q2_2 = BlocksWalkedQuest::new(BlockType::Grass, 1, 1);
            let q2 = Box::new(ThenQuest::new(q2_1, q2_2));
            let q3 = Box::new(BlocksWalkedQuest::new(BlockType::Water, 9, 3));

            let q: Box<dyn Quest<QuestEvent>> =
                Box::new(AtLeastNumQuests::new(vec![q1, q2, q3], 2));
            Some(q)
        }
        _ => None,
    }
}
