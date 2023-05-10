//! This module contains the single quest types.

use std::fmt::Display;
use crate::quest::{BlockType, Quest, QuestEvent, QuestStatus};


/// A quest that requires the player to collect a specific type of block.
#[derive(Debug, Clone, Copy)]
pub struct BlocksWalkedQuest {
    /// The type of block that the player needs to walk on.
    pub blocks_type: BlockType,
    /// The number of blocks that the player needs to walk on.
    pub target_blocks: u8,
    /// The number of blocks that the player has walked on.
    pub blocks_walked: u8,
    /// The number of times that the player needs to complete this quest.
    pub repeat_times: u8,
    /// The number of times that the player has completed this quest.
    pub repeat_count: u8,
}

impl BlocksWalkedQuest {
    /// Create a new quest that requires the player to collect a specific type of block.
    ///
    /// # Arguments
    /// * `blocks_type` - The type of block that the player needs to walk on.
    /// * `target_blocks` - The number of blocks that the player needs to walk on.
    /// * `repeat_times` - The number of times that the player needs to complete this quest.
    ///
    /// # Example
    /// ```
    /// use adventurers_quest::quest_single::BlocksWalkedQuest;
    /// use adventurers_quest::quest::{Quest, BlockType, QuestStatus};
    ///
    /// let quest = BlocksWalkedQuest::new(BlockType::Grass, 10, 1);
    /// assert_eq!(quest.blocks_type, BlockType::Grass);
    /// assert_eq!(quest.target_blocks, 10);
    /// assert_eq!(quest.blocks_walked, 0);
    /// assert_eq!(quest.repeat_times, 1);
    /// assert_eq!(quest.repeat_count, 0);
    /// assert_eq!(quest.is_complete(), QuestStatus::Ongoing);
    /// ```
    pub fn new(blocks_type: BlockType, target_blocks: u8, repeat_times: u8) -> Self {
        Self {
            blocks_type,
            target_blocks,
            blocks_walked: 0,
            repeat_times,
            repeat_count: 0,
        }
    }
}

impl Display for BlocksWalkedQuest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status = <dyn Quest<QuestEvent>>::get_complete_sign(self);
        let remaining = self.target_blocks - self.blocks_walked;
        if self.repeat_times == 1 {
            if remaining > 1 {
                write!(
                    f,
                    "[{}] Walk on a {} block..\n ^ (complete {} more times)",
                    status, self.blocks_type, remaining
                )
            } else {
                write!(f, "[{}] Walk on a {} block..\n", status, self.blocks_type)
            }
        } else {
            if remaining > 1 {
                write!(
                    f,
                    "[{}] Walk through exactly {} blocks of {}\n ^ (complete {} more times)",
                    status,
                    self.target_blocks,
                    self.blocks_type,
                    self.repeat_times - self.repeat_count
                )
            } else {
                write!(
                    f,
                    "[{}] Walk through exactly {} blocks of {}",
                    status, self.target_blocks, self.blocks_type
                )
            }
        }
    }
}

impl Quest<QuestEvent> for BlocksWalkedQuest {
    /// Whenever something happens, you call "register_event" to tell the quest what's happened.
    /// The quest will update its status accordingly.
    ///
    /// # Arguments
    /// * `event` - The event that happened.
    ///
    /// # Example
    /// ```
    /// use adventurers_quest::quest::{Quest, QuestEvent, BlockType, QuestStatus};
    /// use adventurers_quest::quest_single::BlocksWalkedQuest;
    ///
    /// let mut quest = BlocksWalkedQuest::new(BlockType::Sand, 1, 1);
    /// assert_eq!(quest.is_complete(), QuestStatus::Ongoing);
    /// assert_eq!(format!("{}", quest), "[ ] Walk on a sand block..\n");
    /// quest.register_event(QuestEvent::WalkedOnBlock(BlockType::Sand));
    /// assert_eq!(quest.is_complete(), QuestStatus::Complete);
    /// assert_eq!(format!("{}", quest), "[✅] Walk on a sand block..\n");
    /// ```
    fn register_event(&mut self, event: QuestEvent) {
        if let QuestEvent::WalkedOnBlock(block_type) = event {
            if block_type == self.blocks_type && self.is_complete() == QuestStatus::Ongoing {
                self.blocks_walked += 1;
                if self.blocks_walked >= self.target_blocks {
                    self.repeat_count += 1;
                    if self.repeat_count < self.repeat_times {
                        self.blocks_walked = 0;
                    }
                }
            }
        }
    }

    fn reset(&mut self) {
        self.blocks_walked = 0;
        self.repeat_count = 0;
    }

    fn is_complete(&self) -> QuestStatus {
        (self.repeat_count >= self.repeat_times).into()
    }
}

/// A quest that requires the player to collect a specific type of block.
#[derive(Debug, Clone, Copy)]
pub struct CollectQuest {
    /// The type of block that the player needs to collect.
    pub blocks_type: BlockType,
    /// The number of blocks that the player needs to collect.
    pub target_blocks: u8,
    /// The number of blocks that the player has collected.
    pub blocks_collected: u8,
}

impl CollectQuest {
    /// Create a new quest that requires the player to collect a specific type of block.
    /// This quest can only be used for [`BlockType::Object`].
    ///
    /// # Arguments
    /// * `blocks_type` - The type of block that the player needs to collect.
    /// * `target_blocks` - The number of blocks that the player needs to collect.
    ///
    /// # Example
    /// ```
    /// use adventurers_quest::quest_single::CollectQuest;
    /// use adventurers_quest::quest::{Quest, BlockType, QuestStatus};
    /// let quest = CollectQuest::new(BlockType::Object('x'), 1);
    ///
    /// assert_eq!(quest.blocks_type, BlockType::Object('x'));
    /// assert_eq!(quest.target_blocks, 1);
    /// assert_eq!(quest.blocks_collected, 0);
    /// assert_eq!(quest.is_complete(), QuestStatus::Ongoing);
    ///
    pub fn new(blocks_type: BlockType, target_blocks: u8) -> Self {
        match blocks_type {
            BlockType::Object(_) => Self {
                blocks_type,
                target_blocks,
                blocks_collected: 0,
            },
            _ => {
                panic!("CollectQuest can only be used for objects");
            }
        }
    }
}

impl Display for CollectQuest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status = <dyn Quest<QuestEvent>>::get_complete_sign(self);
        let remaining = self.target_blocks - self.blocks_collected;
        if remaining > 1 {
            write!(
                f,
                "[{}] Collect a {}..\n ^ (complete {} more times)",
                status, self.blocks_type, remaining
            )
        } else {
            write!(f, "[{}] Collect a {}..\n", status, self.blocks_type)
        }
    }
}

impl Quest<QuestEvent> for CollectQuest {
    /// Whenever something happens, you call "register_event" to tell the quest what's happened.
    /// The quest will update its status accordingly.
    ///
    /// # Arguments
    /// * `event` - The event that happened.
    ///
    /// # Example
    /// ```
    /// use adventurers_quest::quest::{Quest, QuestEvent, BlockType, QuestStatus};
    /// use adventurers_quest::quest_single::CollectQuest;
    ///
    /// let mut quest = CollectQuest::new(BlockType::Object('x'), 1);
    /// assert_eq!(quest.is_complete(), QuestStatus::Ongoing);
    /// assert_eq!(format!("{}", quest), "[ ] Collect a 'x'..\n");
    /// quest.register_event(QuestEvent::CollectItem(BlockType::Object('x')));
    /// assert_eq!(quest.is_complete(), QuestStatus::Complete);
    /// assert_eq!(format!("{}", quest), "[✅] Collect a 'x'..\n");
    /// ```
    fn register_event(&mut self, event: QuestEvent) {
        if let QuestEvent::CollectItem(block_type) = event {
            if block_type == self.blocks_type && self.is_complete() == QuestStatus::Ongoing {
                self.blocks_collected += 1;
            }
        }
    }

    fn reset(&mut self) {
        self.blocks_collected = 0;
    }

    fn is_complete(&self) -> QuestStatus {
        (self.blocks_collected >= self.target_blocks).into()
    }
}
